//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Load the TOFU pin cache from disk.
///
/// Maps null_id -> {address, fp, first_seen, last_verified}.
pub fn pin_cache_load() -> HashMap<String, serde_json::Value> {
    let path = pin_cache_path();
    if !path.exists() {
        return HashMap::new();
    }
    match fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

/// Persist the TOFU pin cache to disk.
///
/// SECURITY FIX (H1): File is created with 0o600 permissions so only the
/// owner can read it. Without this, any local user could read pinned
/// addresses and fingerprints.
pub fn pin_cache_save(cache: &HashMap<String, serde_json::Value>) {
    let path = pin_cache_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(cache) {
        // SECURITY FIX (H1): Write with restrictive permissions
        use std::os::unix::fs::OpenOptionsExt;
        if let Ok(mut f) = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
        {
            use std::io::Write;
            let _ = f.write_all(json.as_bytes());
        } else {
            // Fallback: write then set permissions
            let _ = fs::write(&path, &json);
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
    }
}

/// Look up a pinned address for a null ID.
pub fn pin_get(null_id: &str) -> Option<serde_json::Value> {
    pin_cache_load().get(null_id).cloned()
}

/// Update or create a pinned address for a null ID.
///
/// On first sight (TOFU): stores the address.
/// On subsequent sight: only updates if the address matches the pin.
/// Logs a warning on mismatch -- caller decides how to handle.
pub fn pin_update(null_id: &str, address: &str, fingerprint: &str) {
    let mut cache = pin_cache_load();
    let existing = cache.get(null_id).cloned();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    if existing.is_none() {
        // Trust on first use
        cache.insert(
            null_id.to_string(),
            serde_json::json!({
                "address": address,
                "fp": fingerprint,
                "first_seen": now,
                "last_verified": now,
            }),
        );
        tracing::info!("TOFU pin: {} -> {} (first seen)", null_id, address);
    } else if let Some(ref obj) = existing {
        if obj.get("address").and_then(|v| v.as_str()) == Some(address) {
            // Same address -- refresh timestamp
            let mut updated = obj.clone();
            if let Some(obj_mut) = updated.as_object_mut() {
                obj_mut.insert("last_verified".to_string(), serde_json::json!(now));
            }
            cache.insert(null_id.to_string(), updated);
        } else {
            // Address changed -- this could be a MITM or a legitimate move
            let pinned = obj.get("address").and_then(|v| v.as_str()).unwrap_or("?");
            tracing::warn!(
                "TOFU pin MISMATCH for {}: pinned={} new={} (keeping old)",
                null_id,
                pinned,
                address
            );
            return; // do not overwrite
        }
    }

    pin_cache_save(&cache);
}

/// Check if an address matches the pinned address for a null ID.
///
/// Returns true if:
/// - No pin exists yet (first use, will be pinned)
/// - Address matches the pin
///
/// Returns false if address differs from pin (possible MITM).
pub fn pin_verify_address(null_id: &str, address: &str) -> bool {
    match pin_get(null_id) {
        None => true, // no pin yet, TOFU
        Some(obj) => obj.get("address").and_then(|v| v.as_str()) == Some(address),
    }
}

fn pin_cache_path() -> PathBuf {
    let mut p = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    p.push(".add");
    p.push("pin_cache.json");
    p
}

/// Check the bootstrap certificate fingerprint against the pin cache.
///
/// Returns true if:
/// - No pin exists yet (TOFU — first seen)
/// - Fingerprint matches the stored pin
///
/// Logs a warning on mismatch.
///
/// SECURITY FIX (G4): Emits a prominent warning when trusting a new bootstrap
/// server certificate for the first time, alerting the user to verify it.
pub fn bootstrap_pin_check(
    seed_url: &str,
    cert_fp: &str,
    not_before: &str,
    not_after: &str,
) -> bool {
    let mut pin_path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    pin_path.push(".add");
    pin_path.push("bootstrap_pin_cache.json");

    let cache: HashMap<String, serde_json::Value> = if pin_path.exists() {
        match fs::read_to_string(&pin_path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => HashMap::new(),
        }
    } else {
        HashMap::new()
    };

    // Check if we have a pin for this seed
    if let Some(existing) = cache.get(seed_url) {
        let pinned_fp = existing.get("fp").and_then(|v| v.as_str()).unwrap_or("");
        if pinned_fp == cert_fp {
            true
        } else {
            tracing::warn!(
                "bootstrap pin MISMATCH for {}: pinned={} current={} (rejecting)",
                seed_url,
                pinned_fp,
                cert_fp
            );
            false
        }
    } else {
        // TOFU: store the pin
        // SECURITY FIX (G4): Log a prominent warning for first-time bootstrap pin
        // so user is aware this is a trust-on-first-use decision
        tracing::warn!(
            "SECURITY NOTICE: First contact with bootstrap server '{}'. No prior pin found. \
             Fingerprint {} is being trusted. If compromised, your identity could be hijacked.",
            seed_url,
            cert_fp
        );
        let mut new_cache = cache;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        new_cache.insert(
            seed_url.to_string(),
            serde_json::json!({
                "fp": cert_fp,
                "not_before": not_before,
                "not_after": not_after,
                "first_seen": now,
                "last_verified": now,
            }),
        );
        // SECURITY FIX (H1): Write with restrictive permissions
        if let Ok(json) = serde_json::to_string_pretty(&new_cache) {
            use std::os::unix::fs::OpenOptionsExt;
            if let Ok(mut f) = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&pin_path)
            {
                use std::io::Write;
                let _ = f.write_all(json.as_bytes());
            } else {
                let _ = fs::write(&pin_path, &json);
                let _ = fs::set_permissions(&pin_path, fs::Permissions::from_mode(0o600));
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_cache_roundtrip() {
        let test_id = "NN-TEST-PINN";
        let test_addr = "wss://example.com:9001";
        let test_fp = "AABBCCDDEEFF00112233445566778899AABBCCDD";

        pin_update(test_id, test_addr, test_fp);

        let pinned = pin_get(test_id);
        assert!(pinned.is_some());
        let pinned = pinned.unwrap();
        assert_eq!(pinned.get("address").unwrap().as_str().unwrap(), test_addr);
        assert_eq!(pinned.get("fp").unwrap().as_str().unwrap(), test_fp);

        assert!(pin_verify_address(test_id, test_addr));
        assert!(!pin_verify_address(test_id, "wss://evil.com:9001"));

        // Clean up
        let mut cache = pin_cache_load();
        cache.remove(test_id);
        pin_cache_save(&cache);
    }
}
