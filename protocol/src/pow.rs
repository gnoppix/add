//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};

use crate::constants;

/// Count leading zero bits in a byte slice.
fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut bits = 0u32;
    for &byte in hash {
        if byte == 0 {
            bits += 8;
        } else {
            let mut b = byte;
            while b > 0 && (b & 0x80) == 0 {
                bits += 1;
                b <<= 1;
            }
            break;
        }
    }
    bits
}

/// Custom error type for PoW operations.
#[derive(Debug, thiserror::Error)]
pub enum PowError {
    #[error("Argon2id parameter error: {0}")]
    Argon2Params(String),
    #[error("Argon2id hashing error: {0}")]
    Argon2Hash(String),
    #[error("PoW difficulty too high - no valid nonce found within max attempts")]
    DifficultyTooHigh,
    #[error("PoW solver timed out (wall-clock budget exceeded)")]
    Timeout,
    #[error("PoW difficulty {0} is below minimum allowed ({1})")]
    DifficultyTooLow(u32, u32),
}

/// Derive a per-node salt from the static POW_SALT and a node secret.
///
/// SECURITY FIX (M11): Concatenates the shared POW_SALT with a per-node
/// secret to produce a unique salt per node. This prevents attackers from
/// precomputing PoW solutions that work across all DHT nodes.
pub fn node_pow_salt(node_secret: &[u8]) -> Vec<u8> {
    let mut salt = constants::POW_SALT.to_vec();
    salt.extend_from_slice(node_secret);
    salt
}

/// Verify Argon2id PoW: check that hash has at least `difficulty` leading zero bits.
///
/// SECURITY: Argon2id-only. No SHA-256 fallback - this ensures memory-hard
/// PoW is always used, maintaining GPU/ASIC resistance.
///
/// SECURITY FIX (M11): `node_secret` is mixed into the salt to make PoW
/// computation unique per node. Without this, all nodes share the same
/// static salt, allowing attackers to precompute PoW solutions.
pub fn pow_check(
    data: &str,
    nonce: u64,
    difficulty: u32,
    node_secret: &[u8],
) -> Result<bool, PowError> {
    // SECURITY FIX (M9): Enforce minimum PoW difficulty.
    if difficulty < constants::MIN_POW_DIFFICULTY {
        return Err(PowError::DifficultyTooLow(
            difficulty,
            constants::MIN_POW_DIFFICULTY,
        ));
    }

    let params = Params::new(
        constants::DHT_POW_MEMORY_COST,
        constants::DHT_POW_TIME_COST,
        constants::DHT_POW_PARALLELISM,
        Some(constants::DHT_POW_HASH_LEN),
    )
    .map_err(|e| PowError::Argon2Params(e.to_string()))?;

    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // SECURITY FIX (M8): Use length-prefixed input to prevent ambiguity.
    // Without delimiter, data="ab" + nonce="c12" == data="abc" + nonce="12".
    // The colon delimiter ensures unique input for every (data, nonce) pair.
    let secret = format!("{}:{}", data, nonce);

    // SECURITY FIX (M11): Per-node salt = POW_SALT || node_secret
    let salt = node_pow_salt(node_secret);

    let mut raw = [0u8; constants::DHT_POW_HASH_LEN];
    hasher
        .hash_password_into(secret.as_bytes(), &salt, &mut raw)
        .map_err(|e| PowError::Argon2Hash(e.to_string()))?;

    Ok(leading_zero_bits(&raw) >= difficulty)
}

/// Find a nonce such that Argon2id(data, nonce) has >= `difficulty` leading zero bits.
///
/// SECURITY: Argon2id-only. Returns error if memory allocation fails instead
/// of falling back to SHA-256 hashcash.
///
/// SECURITY FIX (M11): `node_secret` is mixed into the salt to make PoW
/// computation unique per node. Callers should pass `None` for situations
/// where no per-node secret is relevant (e.g., P2P hello).
pub fn pow_solve(
    data: &str,
    difficulty: u32,
    max_attempts: u64,
    node_secret: &[u8],
) -> Result<Option<u64>, PowError> {
    // SECURITY FIX (M9): Enforce minimum PoW difficulty.
    if difficulty < constants::MIN_POW_DIFFICULTY {
        return Err(PowError::DifficultyTooLow(
            difficulty,
            constants::MIN_POW_DIFFICULTY,
        ));
    }

    let params = Params::new(
        constants::DHT_POW_MEMORY_COST,
        constants::DHT_POW_TIME_COST,
        constants::DHT_POW_PARALLELISM,
        Some(constants::DHT_POW_HASH_LEN),
    )
    .map_err(|e| PowError::Argon2Params(e.to_string()))?;

    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let salt = node_pow_salt(node_secret);

    // Wall-clock budget so the solver can never grind for minutes on a slow
    // host (Argon2id@1MB is memory-hard; difficulty 12 could take >30s on a
    // constrained VPS). Bounded by real time, not just attempt count.
    let budget = std::time::Duration::from_secs(30);
    let start = std::time::Instant::now();

    for nonce in 0..max_attempts {
        // SECURITY FIX (M8): Use length-prefixed input to prevent ambiguity.
        let secret = format!("{}:{}", data, nonce);
        let mut raw = [0u8; constants::DHT_POW_HASH_LEN];
        hasher
            .hash_password_into(secret.as_bytes(), &salt, &mut raw)
            .map_err(|e| PowError::Argon2Hash(e.to_string()))?;

        if leading_zero_bits(&raw) >= difficulty {
            return Ok(Some(nonce));
        }

        // Check the budget at a coarse stride to avoid a syscall per attempt.
        if nonce % 1024 == 0 && start.elapsed() > budget {
            return Err(PowError::Timeout);
        }
    }
    Ok(None)
}

// SECURITY: SHA-256 PoW functions removed - they provided an insecure fallback path
// that could be exploited to bypass GPU/ASIC-resistant Argon2id memory-hard PoW.
// If Argon2id memory allocation fails, the operation fails hard rather than falling
// back to fast hashcash. This maintains the ~500,000x botnet throughput reduction.

/// Compute SHA-256 hex digest.
///
/// NOTE: This is kept for fingerprinting and other non-PoW uses. It is NOT used
/// for proof-of-work anymore - use `pow_check` and `pow_solve` for PoW operations.
pub fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, data.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute BLAKE2b-8 hex digest.
pub fn blake2b_8_hex(data: &str) -> String {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};

    let mut hasher = Blake2bVar::new(8).expect("blake2b with 8 bytes is valid");
    Update::update(&mut hasher, data.as_bytes());
    let mut result = [0u8; 8];
    let _ = hasher.finalize_variable(&mut result);
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_pow_low_difficulty() {
        // Difficulty 8 is the minimum allowed (MIN_POW_DIFFICULTY)
        let node_secret = b"test-node-secret";
        let nonce = pow_solve("test", 8, 100000, node_secret).unwrap().unwrap();
        assert!(pow_check("test", nonce, 8, node_secret).unwrap());
    }

    #[test]
    fn test_argon2_pow_per_node_salt() {
        // SECURITY FIX (M11): PoW solutions must be unique per node.
        // A nonce found for one node_secret must NOT verify for a different node_secret.
        let secret_a = b"node-alpha-secret";
        let secret_b = b"node-beta-secret";
        let nonce = pow_solve("test", 8, 100000, secret_a).unwrap().unwrap();
        // Should verify for node A
        assert!(pow_check("test", nonce, 8, secret_a).unwrap());
        // Should NOT verify for node B (different salt)
        assert!(!pow_check("test", nonce, 8, secret_b).unwrap());
    }

    #[test]
    fn test_pow_minimum_difficulty_enforcement() {
        // SECURITY FIX (M9): Difficulty below MIN_POW_DIFFICULTY must be rejected.
        let node_secret = b"test-node-secret";

        // pow_solve should reject difficulty < 8
        let result = pow_solve("test", 0, 10000, node_secret);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PowError::DifficultyTooLow(0, 8)
        ));

        let result = pow_solve("test", 7, 10000, node_secret);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PowError::DifficultyTooLow(7, 8)
        ));

        // pow_check should reject difficulty < 8
        let result = pow_check("test", 0, 0, node_secret);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PowError::DifficultyTooLow(0, 8)
        ));

        let result = pow_check("test", 0, 5, node_secret);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PowError::DifficultyTooLow(5, 8)
        ));

        // Exactly MIN_POW_DIFFICULTY should be accepted (not rejected)
        // Note: we don't actually solve, just verify the check doesn't reject it.
        // pow_check with difficulty=8 will return Ok(false) for a random nonce, not an error.
        let result = pow_check("test", 0, 8, node_secret);
        assert!(result.is_ok());

        let result = pow_solve("test", 8, 1, node_secret);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sha256_hex() {
        let h = sha256_hex("hello world");
        assert_eq!(
            h,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_blake2b_8_hex() {
        let h = blake2b_8_hex("test_fingerprint");
        assert_eq!(h.len(), 16); // 8 bytes = 16 hex chars
    }
}
