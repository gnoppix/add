//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Licence: Business Source License (BSL / BUSL)
//
// TPM 2.0 hardware-bound Master App Key vault.
//
// Strategy (Key Wrapping / Data Sealing): the app generates a random 256-bit
// Master App Key (MAK) locally. The MAK encrypts the on-disk ML-DSA-87 signing
// seed (fixing audit [1]). The MAK itself is protected two ways:
//
//   * TPM mode (Linux/Windows with a chip): the MAK is sealed to the TPM's
//     Storage Root Key (persistent handle 0x81000001). The seal object carries
//     an authValue = SHA-256(PIN), so the TPM *hardware-enforces* the 6-digit
//     PIN (wrong PIN => TPM2_RC_AUTH_FAIL, MAK never leaves the chip). The blob
//     is TPM-encrypted to the SRK, so it is useless if extracted off-device.
//
//   * Passphrase mode (macOS / no TPM): the MAK is AES-256-GCM(MAK,
//     Argon2id(16-char password)) and stored as JSON. No device binding, but
//     high password entropy.
//
// The VaultFile on disk is an enum so the client can detect which mode was
// used at first run and route unlock accordingly.
//-------------------------------------------------------------------------------

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;
use rand::RngCore;

/// Length of the Master App Key in bytes (AES-256).
pub const MAK_LEN: usize = 32;

/// The Master App Key. Zeroized on drop; never serialised in plaintext.
#[derive(ZeroizeOnDrop, Clone)]
pub struct MasterAppKey {
    material: ZeroizingMak,
}

#[derive(ZeroizeOnDrop, Clone)]
struct ZeroizingMak(Box<[u8; MAK_LEN]>);

impl MasterAppKey {
    /// Generate a fresh random 256-bit MAK.
    pub fn generate() -> Result<Self, CryptoError> {
        use rand::RngCore;
        let mut buf = Box::new([0u8; MAK_LEN]);
        rand::thread_rng().fill_bytes(&mut buf[..]);
        Ok(Self {
            material: ZeroizingMak(buf),
        })
    }

    /// Wrap an existing raw key.
    pub fn from_raw(raw: [u8; MAK_LEN]) -> Self {
        Self {
            material: ZeroizingMak(Box::new(raw)),
        }
    }

    /// Borrow the raw bytes.
    pub fn as_bytes(&self) -> &[u8; MAK_LEN] {
        &self.material.0
    }
}

/// On-disk vault format.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultFile {
    pub version: u8,
    pub kind: VaultKind,
    /// Passphrase mode only: stored Argon2id salt (b64) for re-deriving the KEK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pw_salt_b64: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "t", content = "d")]
pub enum VaultKind {
    /// TPM-sealed blob: base64 of (TPM2B_PRIVATE || TPM2B_PUBLIC).
    Tpm { sealed_b64: String },
    /// Passphrase mode: base64 of AES-256-GCM(MAK, nonce||ct).
    Passphrase { wrapped_b64: String },
}

impl VaultFile {
    /// Write the vault to `path` with 0o600 permissions.
    pub fn write_to(&self, path: &std::path::Path) -> Result<(), CryptoError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| CryptoError::Serialization(format!("vault serialize: {e}")))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CryptoError::Io(format!("vault mkdir: {e}")))?;
        }
        std::fs::write(path, json).map_err(|e| CryptoError::Io(format!("vault write: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| CryptoError::Io(format!("vault chmod: {e}")))?;
        }
        Ok(())
    }

    /// Read + parse a vault file.
    pub fn read_from(path: &std::path::Path) -> Result<Self, CryptoError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| CryptoError::Io(format!("vault read: {e}")))?;
        serde_json::from_str(&content)
            .map_err(|e| CryptoError::Serialization(format!("vault parse: {e}")))
    }
}

// ============================================================================
// Passphrase mode (always available, no TPM required)
// ============================================================================

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2,
};
use base64::engine::{general_purpose::STANDARD as B64, Engine};

/// Argon2id parameters for the password -> KEK derivation.
const ARGON2_MEMORY_KIB: u32 = 19456; // ~19 MiB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

/// Failed unlock attempts counter (used for self-destruct after N wrong tries).
/// Stored as JSON in ~/.add/failed_attempts.json.
fn max_wrong_attempts() -> u8 {
    // Try to read from settings file
    let home = if let Some(h) = dirs::home_dir() {
        h
    } else {
        return 10;
    };
    let settings_path = home.join(".add/settings.json");
    if let Ok(content) = std::fs::read_to_string(&settings_path) {
        if let Ok(settings) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(threshold) = settings.get("selfDestructThreshold").and_then(|v| v.as_u64()) {
                return threshold.clamp(3, 20) as u8; // Configurable: 3-20 attempts
            }
        }
    }
    10 // Default: 10 attempts
}

/// Increment the failed-attempt counter, return Ok(true) if self-destruct should trigger.
pub fn check_failed_attempts(home: &std::path::Path, increment: bool) -> Result<bool, CryptoError> {
    let path = home.join(".add/failed_attempts.json");
    let mut count: u8 = if path.exists() {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| CryptoError::Io(format!("failed-read: {e}")))?;
        serde_json::from_str(&content).unwrap_or(0)
    } else {
        0
    };

    if increment {
        count = count.saturating_add(1);
        if count >= max_wrong_attempts() {
            // Return true to trigger self-destruct (caller handles purge)
            return Ok(true);
        }
        // Persist the incremented counter
        let json = serde_json::to_string(&count)
            .map_err(|e| CryptoError::Serialization(format!("failed-serialize: {e}")))?;
        std::fs::write(&path, json).map_err(|e| CryptoError::Io(format!("failed-write: {e}")))?;
    }

    Ok(false)
}

/// Reset the failed-attempt counter (called on successful unlock).
pub fn reset_failed_attempts(home: &std::path::Path) -> Result<(), CryptoError> {
    let path = home.join(".add/failed_attempts.json");
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| CryptoError::Io(format!("failed-remove: {e}")))?;
    }
    Ok(())
}

/// Nuclear wipe: delete all identity/vault/message data.
pub fn self_destruct(home: &std::path::Path) -> Result<(), CryptoError> {
    let add_dir = home.join(".add");
    if add_dir.exists() {
        let _ = std::fs::remove_dir_all(&add_dir);
    }
    Ok(())
}

/// Argon2id(password, salt) -> 32-byte KEK.
fn derive_kek(credential: &[u8], salt: &SaltString) -> Result<[u8; 32], CryptoError> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(32),
        )
        .map_err(|e| CryptoError::DerivationFailed(e.to_string()))?,
    );
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(credential, salt.as_str().as_bytes(), &mut out)
        .map_err(|e| CryptoError::DerivationFailed(e.to_string()))?;
    Ok(out)
}

/// AES-256-GCM wrap of `plaintext` under `kek`. Output: nonce(12) || ct || tag.
fn aes_wrap(kek: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: b"add-mak-v1" })
        .map_err(|e| CryptoError::EncryptFailed(format!("aes-wrap: {e}")))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AES-256-GCM unwrap. Input: nonce(12) || ct || tag.
fn aes_unwrap(kek: &[u8; 32], wrapped: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if wrapped.len() < 12 {
        return Err(CryptoError::DecryptFailed("aes-unwrap: too short".into()));
    }
    let (nonce, ct) = wrapped.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: b"add-mak-v1" })
        .map_err(|_| {
            CryptoError::DecryptFailed("aes-unwrap: auth failed (bad password)".into())
        })
}

/// Seal the MAK under a 16-char password -> VaultFile (Passphrase).
pub fn seal_with_passphrase(
    mak: &MasterAppKey,
    password: &[u8],
) -> Result<VaultFile, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let kek = derive_kek(password, &salt)?;
    let wrapped = aes_wrap(&kek, mak.as_bytes())?;
    Ok(VaultFile {
        version: 1,
        kind: VaultKind::Passphrase {
            wrapped_b64: B64.encode(&wrapped),
        },
        pw_salt_b64: Some(salt.as_str().to_string()),
    })
}

/// Unseal a Passphrase vault -> MAK.
pub fn unseal_with_passphrase(
    vault: &VaultFile,
    password: &[u8],
) -> Result<MasterAppKey, CryptoError> {
    let VaultKind::Passphrase { wrapped_b64 } = &vault.kind else {
        return Err(CryptoError::DecryptFailed("vault is not passphrase mode".into()));
    };
    let salt = vault
        .pw_salt_b64
        .as_deref()
        .ok_or_else(|| CryptoError::DecryptFailed("passphrase vault missing salt".into()))?;
    let salt = SaltString::from_b64(salt)
        .map_err(|e| CryptoError::DecryptFailed(format!("bad salt: {e}")))?;
    let wrapped = B64
        .decode(wrapped_b64)
        .map_err(|e| CryptoError::DecryptFailed(format!("bad wrapped b64: {e}")))?;
    let kek = derive_kek(password, &salt)?;
    let mut raw = aes_unwrap(&kek, &wrapped)?;
    if raw.len() != MAK_LEN {
        return Err(CryptoError::DecryptFailed("unexpected MAK length".into()));
    }
    let mut buf = [0u8; MAK_LEN];
    buf.copy_from_slice(&raw);
    raw.zeroize();
    Ok(MasterAppKey::from_raw(buf))
}

/// Encrypt arbitrary bytes (e.g. the ML-DSA-87 signing seed) at rest using the
/// Master App Key. Output: nonce(12) || ct || tag. Fixes audit [1] — the PQ
/// seed is never written to disk in plaintext; it is bound to the MAK, which is
/// itself TPM-sealed (or passphrase-wrapped) and never present in plaintext
/// outside secure RAM.
pub fn encrypt_with_mak(mak: &MasterAppKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    aes_wrap(mak.as_bytes(), plaintext)
}

/// Decrypt bytes previously produced by `encrypt_with_mak`.
pub fn decrypt_with_mak(mak: &MasterAppKey, wrapped: &[u8]) -> Result<Vec<u8>, CryptoError> {
    aes_unwrap(mak.as_bytes(), wrapped)
}

/// Cache the MAK in a thread-local for the duration of the process.
/// This is a simple in-RAM cache; the MAK is zeroized when dropped.
pub fn cache_mak(mak: MasterAppKey) {
    MAK_CACHE.with(|c| c.borrow_mut().replace(mak));
}

/// Retrieve the cached MAK (if any). Returns None if not unlocked.
pub fn get_cached_mak() -> Option<MasterAppKey> {
    MAK_CACHE.with(|c| c.borrow().as_ref().map(|m| m.clone()))
}

thread_local! {
    static MAK_CACHE: std::cell::RefCell<Option<MasterAppKey>> = const { std::cell::RefCell::new(None) };
}

// ============================================================================
// TPM mode (feature-gated; Linux/Windows with a TPM 2.0 chip)
// ============================================================================

#[cfg(feature = "tpm")]
mod tpm {
    use super::*;
    use tss_esapi::{
        attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
        constants::session_type::SessionType,
        handles::{KeyHandle, PersistentTpmHandle, TpmHandle},
        interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm},
        structures::{
            Auth, KeyedHashScheme, Public, PublicBuilder, PublicKeyedHashParameters,
            SensitiveData, SymmetricDefinition,
        },
        utils::TpmsContext,
        Context, TctiNameConf,
    };

    /// Persistent SRK handle used as the seal parent.
    const SRK_PERSISTENT: u32 = 0x8100_0001;

    /// SHA-256(PIN) used as the TPM object authValue (hardware-enforced PIN gate).
    fn pin_auth_value(pin: &[u8]) -> Auth {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"add-pin-v1");
        h.update(pin);
        let d = h.finalize();
        let mut v = [0u8; 32];
        v.copy_from_slice(&d);
        Auth::try_from(v.as_slice()).expect("32-byte auth")
    }

    /// Open an ESYS context against the system TPM (resource manager) with an
    /// HMAC auth session established (required for `create`/`load`/`unseal`).
    fn open_context() -> Result<Context, CryptoError> {
        let tcti = TctiNameConf::Device(Default::default());
        let mut ctx =
            Context::new(tcti).map_err(|e| CryptoError::HardwareError(format!("ESYS init: {e:?}")))?;

        let session = ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(|e| CryptoError::HardwareError(format!("start session: {e:?}")))?;
        let (attrs, mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        let s = session.ok_or_else(|| CryptoError::HardwareError("TPM returned no auth session".into()))?;
        ctx.tr_sess_set_attributes(s, attrs, mask)
            .map_err(|e| CryptoError::HardwareError(format!("session attrs: {e:?}")))?;
        ctx.set_sessions((Some(s), None, None));
        Ok(ctx)
    }

    /// Resolve the persistent SRK as a loaded parent key handle.
    fn srk_handle(ctx: &mut Context) -> Result<KeyHandle, CryptoError> {
        let persistent = PersistentTpmHandle::new(SRK_PERSISTENT)
            .map_err(|e| CryptoError::HardwareError(format!("srk handle: {e:?}")))?;
        let obj = ctx
            .tr_from_tpm_public(TpmHandle::Persistent(persistent))
            .map_err(|e| CryptoError::HardwareError(format!("srk load: {e:?}")))?;
        Ok(KeyHandle::from(obj))
    }

    /// Build a KEYEDHASH sealing template with userWithAuth + fixedTPM/parent.
    fn seal_template() -> Result<Public, CryptoError> {
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_user_with_auth(true)
            .with_sensitive_data_origin(false)
            .build()
            .map_err(|e| CryptoError::HardwareError(format!("attrs: {e:?}")))?;
        let params = PublicKeyedHashParameters::new(KeyedHashScheme::Null);
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .with_keyed_hash_parameters(params)
            .with_keyed_hash_unique_identifier(Default::default())
            .build()
            .map_err(|e| CryptoError::HardwareError(format!("template: {e:?}")))
    }

    /// Seal `plaintext` (the raw MAK) to the TPM under the PIN authValue.
    /// Returns a serde-serialized `TpmsContext` (the saved sealed object) as bytes.
    pub fn tpm_seal(plaintext: &[u8], pin: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut ctx = open_context()?;
        let parent = srk_handle(&mut ctx)?;
        let auth = pin_auth_value(pin);

        let sensitive = SensitiveData::try_from(plaintext)
            .map_err(|e| CryptoError::HardwareError(format!("data: {e:?}")))?;
        let template = seal_template()?;

        let result = ctx
            .create(parent, template, Some(auth), Some(sensitive), None, None)
            .map_err(|e| CryptoError::HardwareError(format!("create: {e:?}")))?;

        // Load the freshly created sealed object, then persist it as a TPM
        // context blob (this is the supported tss-esapi persistence path and
        // serializes cleanly to disk via serde).
        let loaded = ctx
            .load(parent, result.out_private, result.out_public)
            .map_err(|e| CryptoError::HardwareError(format!("load: {e:?}")))?;

        let saved: TpmsContext = ctx
            .context_save(loaded.into())
            .map_err(|e| CryptoError::HardwareError(format!("context_save: {e:?}")))?;

        serde_json::to_vec(&saved)
            .map_err(|e| CryptoError::HardwareError(format!("serialize ctx: {e:?}")))
    }

    /// Unseal a TPM context blob previously produced by `tpm_seal`.
    pub fn tpm_unseal(blob: &[u8], pin: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut ctx = open_context()?;

        let saved: TpmsContext = serde_json::from_slice(blob)
            .map_err(|e| CryptoError::HardwareError(format!("deserialize ctx: {e:?}")))?;

        let loaded = ctx
            .context_load(saved)
            .map_err(|e| CryptoError::HardwareError(format!("context_load: {e:?}")))?;

        // Set the PIN-derived auth on the loaded object, then unseal. Wrong PIN
        // => TPM2_RC_AUTH_FAIL and the MAK is never revealed.
        let auth = pin_auth_value(pin);
        ctx.tr_set_auth(loaded, auth)
            .map_err(|e| CryptoError::HardwareError(format!("setauth: {e:?}")))?;

        let inner = ctx
            .unseal(loaded)
            .map_err(|e| CryptoError::DecryptFailed(format!("tpm unseal (bad PIN?): {e:?}")))?;

        Ok(inner.to_vec())
    }
}

#[cfg(feature = "tpm")]
pub use tpm::{tpm_seal, tpm_unseal};

#[cfg(feature = "tpm")]
impl VaultFile {
    /// Seal MAK to TPM under a 6-digit PIN.
    pub fn seal_to_tpm(mak: &MasterAppKey, pin: &[u8]) -> Result<VaultFile, CryptoError> {
        let blob = tpm_seal(mak.as_bytes(), pin)?;
        Ok(VaultFile {
            version: 1,
            kind: VaultKind::Tpm {
                sealed_b64: B64.encode(&blob),
            },
            pw_salt_b64: None,
        })
    }

    /// Unseal a TPM vault under the PIN -> MAK.
    pub fn unseal_from_tpm(&self, pin: &[u8]) -> Result<MasterAppKey, CryptoError> {
        let VaultKind::Tpm { sealed_b64 } = &self.kind else {
            return Err(CryptoError::DecryptFailed("vault is not TPM mode".into()));
        };
        let blob = B64
            .decode(sealed_b64)
            .map_err(|e| CryptoError::DecryptFailed(format!("bad sealed b64: {e}")))?;
        let mut raw = tpm_unseal(&blob, pin)?;
        if raw.len() != MAK_LEN {
            return Err(CryptoError::DecryptFailed("unexpected MAK length".into()));
        }
        let mut buf = [0u8; MAK_LEN];
        buf.copy_from_slice(&raw);
        raw.zeroize();
        Ok(MasterAppKey::from_raw(buf))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_roundtrip_and_wrong_pw_fails() {
        let mak = MasterAppKey::from_raw([7u8; MAK_LEN]);
        let pw = b"Ab1!Cd2#Ef3@Gh4$"; // 16 chars, mixed classes
        let vault = seal_with_passphrase(&mak, pw).unwrap();
        assert!(matches!(vault.kind, VaultKind::Passphrase { .. }));

        // Round-trip.
        let out = unseal_with_passphrase(&vault, pw).unwrap();
        assert_eq!(out.as_bytes(), mak.as_bytes());

        // Wrong password must NOT reveal the MAK.
        let bad = unseal_with_passphrase(&vault, b"WR0NGp4$$w0rd12X");
        assert!(bad.is_err(), "wrong password should fail to unseal");
    }

    #[test]
    fn passphrase_vault_file_persist() {
        let mak = MasterAppKey::from_raw([9u8; MAK_LEN]);
        let vault = seal_with_passphrase(&mak, b"Zx9!Yw8@Vq7#Mn6$").unwrap();
        let dir = std::env::temp_dir();
        let p = dir.join(format!("add_vault_test_{}.json", std::process::id()));
        vault.write_to(&p).unwrap();
        let loaded = VaultFile::read_from(&p).unwrap();
        let out = unseal_with_passphrase(&loaded, b"Zx9!Yw8@Vq7#Mn6$").unwrap();
        assert_eq!(out.as_bytes(), mak.as_bytes());
        let _ = std::fs::remove_file(&p);
    }

    // Audit [1] fix: the ML-DSA seed must be encrypted at rest with the MAK.
    #[test]
    fn mak_encrypts_seed_at_rest() {
        // Simulated ML-DSA-87 seed (64-byte expanded seed).
        let seed = [0xABu8; 64];
        let mak = MasterAppKey::from_raw([1u8; MAK_LEN]);

        let wrapped = encrypt_with_mak(&mak, &seed).unwrap();
        assert_ne!(&wrapped[..], &seed[..], "seed must not be stored in plaintext");

        let recovered = decrypt_with_mak(&mak, &wrapped).unwrap();
        assert_eq!(recovered, seed);

        // Wrong MAK must fail to decrypt.
        let wrong = MasterAppKey::from_raw([2u8; MAK_LEN]);
        assert!(decrypt_with_mak(&wrong, &wrapped).is_err());
    }

    // TPM-mode round-trip against the real chip. Requires root/`tss` access to
    // the TPM resource manager, so it is only run when ADD_TPM_TEST=1 is set
    // (e.g. `sudo ADD_TPM_TEST=1 cargo test -p add-crypto --features tpm`).
    #[test]
    #[cfg(feature = "tpm")]
    fn tpm_roundtrip_and_wrong_pin_fails() {
        if std::env::var("ADD_TPM_TEST").is_err() {
            eprintln!("skipping tpm_roundtrip (set ADD_TPM_TEST=1 to run on real chip)");
            return;
        }
        let mak = MasterAppKey::from_raw([3u8; MAK_LEN]);
        let pin = b"123456";
        let vault = VaultFile::seal_to_tpm(&mak, pin).unwrap();
        assert!(matches!(vault.kind, VaultKind::Tpm { .. }));

        // Correct PIN unseals to the same MAK.
        let out = vault.unseal_from_tpm(pin).unwrap();
        assert_eq!(out.as_bytes(), mak.as_bytes());

        // Wrong PIN must be rejected by the TPM (auth failure, MAK never leaves).
        let bad = vault.unseal_from_tpm(b"000000");
        assert!(bad.is_err(), "wrong PIN should fail TPM unseal");
    }
}
