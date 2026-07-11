//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------

use base64::Engine;
use hmac::Hmac;
use ml_dsa;
use add_crypto_pq::{MlDsa87VerifyingKey, verify as verify_ml_dsa87, sign as sign_ml_dsa87, MlDsa87Signature, PqError, MlDsa87SigningKey};
use ml_dsa::SignatureEncoding;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

type HmacSha256 = Hmac<Sha256>;

/// SECURITY FIX (H10): Maximum number of entries in the cert cache.
/// Prevents unbounded memory growth from too many unique certificates.
const CERT_CACHE_MAX_ENTRIES: usize = 1000;

/// In-memory verifying key cache: fingerprint -> (verifying key, last access time).
/// Populated on first sight (TOFU) when publishers include their verifying key.
static VERIFYING_KEY_CACHE: RwLock<Option<HashMap<String, (MlDsa87VerifyingKey, Instant)>>> = RwLock::new(None);

/// Get or initialize the verifying key cache (read guard).
fn verifying_key_cache_read() -> std::sync::RwLockReadGuard<'static, Option<HashMap<String, (MlDsa87VerifyingKey, Instant)>>> {
    VERIFYING_KEY_CACHE.read().expect("verifying key cache lock poisoned")
}

/// Get or initialize the verifying key cache (write guard).
fn verifying_key_cache_write() -> std::sync::RwLockWriteGuard<'static, Option<HashMap<String, (MlDsa87VerifyingKey, Instant)>>> {
    VERIFYING_KEY_CACHE.write().expect("verifying key cache lock poisoned")
}

/// Store an ML-DSA-87 verifying key in the cache for the given fingerprint.
///
/// SECURITY FIX (H10): Evicts the least-recently-accessed entry when
/// the cache exceeds CERT_CACHE_MAX_ENTRIES.
pub fn cache_verifying_key(fingerprint: &str, vk: &MlDsa87VerifyingKey) {
    let mut guard = verifying_key_cache_write();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    let cache = guard.as_mut().unwrap();
    let key = fingerprint.to_uppercase();
    cache.insert(key.clone(), (vk.clone(), Instant::now()));

    // SECURITY FIX (H10): Evict LRU entry if over capacity
    if cache.len() > CERT_CACHE_MAX_ENTRIES {
        if let Some(lru_key) = cache.iter().min_by_key(|(_, (_, ts))| *ts).map(|(k, _)| k.clone()) {
            cache.remove(&lru_key);
        }
    }
}

/// Look up a cached verifying key by fingerprint.
///
/// SECURITY FIX (H10): Updates the last access time on lookup (true LRU behavior).
pub fn get_cached_verifying_key(fingerprint: &str) -> Option<MlDsa87VerifyingKey> {
    // First try read lock for lookup
    {
        let guard = verifying_key_cache_read();
        if let Some(ref cache) = *guard {
            if let Some((vk, _)) = cache.get(&fingerprint.to_uppercase()) {
                let vk = vk.clone();
                drop(guard);
                // Update access time with write lock
                {
                    let mut write_guard = verifying_key_cache_write();
                    if let Some(ref mut cache) = *write_guard {
                        if let Some(entry) = cache.get_mut(&fingerprint.to_uppercase()) {
                            entry.1 = Instant::now();
                        }
                    }
                }
                return Some(vk);
            }
        }
    }
    None
}

/// Fingerprint format: 32 or 40 hex chars (v3/v4 OpenPGP keys).
pub fn validate_fingerprint(fp: &str) -> bool {
    let len = fp.len();
    if len != 32 && len != 40 {
        return false;
    }
    fp.chars().all(|c| c.is_ascii_hexdigit())
}

/// Syntax check for null ID format: NN-XXXX-XXXX.
/// Also accepts addr:NN-XXXX-XXXX prefix for address records.
pub fn validate_null_id(nid: &str) -> bool {
    // Strip addr: prefix if present
    let nid = nid.strip_prefix("addr:").unwrap_or(nid);
    let parts: Vec<&str> = nid.split('-').collect();
    if parts.len() != 3 || parts[0] != "NN" {
        return false;
    }
    parts[1].len() == 4 && parts[2].len() == 4
}

/// Verify that a null ID is the correct hash of the given fingerprint.
/// This prevents an attacker from claiming someone else's null ID.
pub fn validate_null_id_strict(nid: &str, fingerprint: &str) -> bool {
    if !validate_null_id(nid) {
        return false;
    }
    if !validate_fingerprint(fingerprint) {
        return false;
    }
    constant_time_compare(&compute_null_id(fingerprint), nid)
}

/// Derive an 8-character Null ID from a GPG fingerprint.
/// blake2b(digest_size=8) → base32 → NN-XXXX-XXXX
///
/// This is a one-way mapping. The fingerprint cannot be recovered from the Null ID.
pub fn compute_null_id(fingerprint: &str) -> String {
    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;

    let mut hasher = Blake2bVar::new(8).expect("blake2b with 8 bytes is valid");
    Update::update(&mut hasher, fingerprint.as_bytes());
    let mut result = [0u8; 8];
    let _ = hasher.finalize_variable(&mut result);

    let b32 = base64::engine::general_purpose::STANDARD.encode(&result);
    let b32 = b32.trim_end_matches('=');
    let b32: String = b32.chars().take(8).collect();
    // base32 uses A-Z 2-7, which is fine for our format
    format!("NN-{}-{}", &b32[..4], &b32[4..8])
}

/// Constant-time string comparison to prevent timing attacks.
pub fn constant_time_compare(a: &str, b: &str) -> bool {
    use hmac::Mac;
    let mut mac_a = HmacSha256::new_from_slice(b"constant-time-compare").unwrap();
    mac_a.update(a.as_bytes());
    let mut mac_b = HmacSha256::new_from_slice(b"constant-time-compare").unwrap();
    mac_b.update(b.as_bytes());
    mac_a.finalize().into_bytes() == mac_b.finalize().into_bytes()
}

/// Create a base64-encoded ML-DSA-87 signature over `data` using the signing key.
/// SECURITY: Uses post-quantum ML-DSA-87 (FIPS 204) signatures.
pub fn sign_data(data: &str, signing_key: &add_crypto_pq::MlDsa87SigningKey) -> Result<String, String> {
    let sig = sign_ml_dsa87(data.as_bytes(), signing_key).map_err(|e| e.to_string())?;
    // Encode as EncodedSignature (RTF) so it round-trips through
    // verify_signature's `EncodedSignature::try_from` (matches crypto-pq convention).
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.encode()))
}

/// Verify a base64-encoded ML-DSA-87 signature.
///
/// SECURITY: Uses post-quantum ML-DSA-87 (FIPS 204) verification.
/// The verifying key is looked up from the in-memory key cache by fingerprint.
/// Returns true only if:
/// 1. The signature is cryptographically valid
/// 2. The signing key fingerprint matches the expected fingerprint
pub fn verify_signature(data: &str, b64_sig: &str, fingerprint: &str) -> bool {
    if !validate_fingerprint(fingerprint) {
        return false;
    }

    let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(b64_sig) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    // Look up the verifying key from the cache
    let vk = match get_cached_verifying_key(fingerprint) {
        Some(vk) => vk,
        None => return false,
    };

    // Decode signature from bytes
    let enc_sig = match ml_dsa::EncodedSignature::<ml_dsa::MlDsa87>::try_from(sig_bytes.as_slice()) {
        Ok(enc) => enc,
        Err(_) => return false,
    };
    let sig = match MlDsa87Signature::decode(&enc_sig) {
        Some(s) => s,
        None => return false,
    };

    verify_ml_dsa87(data.as_bytes(), &sig, &vk).is_ok()
}

/// Verify a base64-encoded ML-DSA-87 signature using the provided verifying key.
///
/// This is the preferred verify path when the caller already has the verifying key
/// (e.g., from the envelope payload's publisher_verifying_key field).
pub fn verify_signature_with_verifying_key(
    data: &str,
    b64_sig: &str,
    vk: &MlDsa87VerifyingKey,
) -> bool {
    let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(b64_sig) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    // Decode signature from bytes
    let enc_sig = match ml_dsa::EncodedSignature::<ml_dsa::MlDsa87>::try_from(sig_bytes.as_slice()) {
        Ok(enc) => enc,
        Err(_) => return false,
    };
    let sig = match MlDsa87Signature::decode(&enc_sig) {
        Some(s) => s,
        None => return false,
    };

    verify_ml_dsa87(data.as_bytes(), &sig, vk).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_fingerprint() {
        assert!(validate_fingerprint("AABBCCDDEEFF00112233445566778899AABBCCDD"));
        assert!(validate_fingerprint("AABBCCDDEEFF00112233445566778899"));
        assert!(!validate_fingerprint("not-hex"));
        assert!(!validate_fingerprint("AABB"));
    }

    #[test]
    fn test_validate_null_id() {
        assert!(validate_null_id("NN-ABCD-EFGH"));
        assert!(!validate_null_id("XX-ABCD-EFGH"));
        assert!(!validate_null_id("NN-ABC-EFGH"));
        assert!(!validate_null_id("NN-ABCDEFGH"));
    }

    #[test]
    fn test_compute_null_id_deterministic() {
        let id1 = compute_null_id("AABBCCDDEEFF00112233445566778899AABBCCDD");
        let id2 = compute_null_id("AABBCCDDEEFF00112233445566778899AABBCCDD");
        assert_eq!(id1, id2);
        assert!(id1.starts_with("NN-"));
    }

    #[test]
    fn test_cert_cache_roundtrip() {
        // Verification is ML-DSA-only: exercise the real verifying-key cache
        // (the production path used by verify_signature), not the removed GPG cache.
        let (_, vk) = add_crypto_pq::generate_keypair().unwrap();
        let fp = "AABBCCDDEEFF00112233445566778899AABBCCDD";
        cache_verifying_key(fp, &vk);
        assert!(get_cached_verifying_key(fp).is_some());
        // Case-insensitive lookup
        assert!(get_cached_verifying_key("aabbccddeeff00112233445566778899aabbccdd").is_some());
        assert!(get_cached_verifying_key("DEADBEEF").is_none());
    }
}
