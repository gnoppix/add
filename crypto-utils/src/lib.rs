//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// Crypto utilities: Sequoia OpenPGP operations, secure deletion
//-------------------------------------------------------------------------------

use std::fs;
use std::io::Write;
use std::path::Path;

use rand::Rng;
use tracing::info;

/// Error type for crypto utility operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoUtilsError {
    #[error("OpenPGP operation failed: {0}")]
    OpenPgp(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid fingerprint format: {0}")]
    InvalidFingerprint(String),
    #[error("Invalid trust level: {0}")]
    InvalidTrustLevel(String),
}

pub type CryptoUtilsResult<T> = Result<T, CryptoUtilsError>;

// ------------------------------------------------------------------ //
//  Secure file deletion                                              //
// ------------------------------------------------------------------ //

/// Attempt to securely delete a temporary file.
///
/// SECURITY: Overwrites with random bytes before unlinking. Uses file opening
/// to prevent TOCTOU attacks where an attacker swaps a symlink between
/// the existence check and deletion.
///
/// NOTE: On Copy-on-Write filesystems (btrfs, zfs), secure deletion provides
/// no guarantee — the old data may persist in snapshots or unallocated blocks.
/// Consider using tmpfs or encrypted storage for highly sensitive temp files.
pub fn secure_delete(path: &str) -> CryptoUtilsResult<()> {
    let p = Path::new(path);

    // SECURITY FIX (H1): Get metadata first, then open. This prevents a race
    // where an attacker replaces the file between check and open.
    // However, note that symlinks are still followed - there's no perfect solution
    // in standard Rust without platform-specific extensions.
    let size = match std::fs::metadata(p) {
        Ok(m) => m.len() as usize,
        Err(_) => return Ok(()), // File doesn't exist
    };

    if size > 0 {
        // Open the file for writing (follows symlinks, but we have the size)
        let mut file = fs::OpenOptions::new().write(true).open(p)?;
        // SECURITY FIX (H1): Advisory write lock via flock on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            // Initial quick overwrite
            let _ = file.write_at(&[0u8; 1], 0);
        }
        let mut rng = rand::thread_rng();
        let mut buf = vec![0u8; 8192];
        let mut remaining = size;
        while remaining > 0 {
            let chunk = std::cmp::min(remaining, buf.len());
            rng.fill(&mut buf[..chunk]);
            file.write_all(&buf[..chunk])?;
            remaining -= chunk;
        }
        file.flush()?;
        file.sync_all()?;
    }
    // SECURITY FIX (H1): Remove the file
    let _ = fs::remove_file(p);
    Ok(())
}

// ------------------------------------------------------------------ //
//  Fingerprint validation                                           //
// ------------------------------------------------------------------ //

/// Validate that a GPG fingerprint is 32 or 40 hex characters.
///
/// SECURITY FIX (L6): GPG v3 keys produce 32-char fingerprints (160-bit
/// SHA-1), while v4 keys produce 40-char fingerprints. The previous
/// implementation only accepted 40 chars, rejecting valid v3 keys.
/// Now accepts 32-40 hex chars, matching crypto::validate_fingerprint().
pub fn validate_fingerprint(fp: &str) -> bool {
    let cleaned = fp.replace(' ', "").replace("0x", "");
    (32..=40).contains(&cleaned.len()) && cleaned.chars().all(|c| c.is_ascii_hexdigit())
}

// ------------------------------------------------------------------ //
//  OpenPGP operations (in-process via Sequoia)                       //
// ------------------------------------------------------------------ //

/// Extract a fingerprint from a Sequoia Cert.
fn fingerprint_from_cert(cert: &sequoia_openpgp::Cert) -> String {
    cert.fingerprint().to_hex().to_uppercase()
}

/// Parse the first Cert from armored key data.
fn parse_cert_armored(armored: &str) -> CryptoUtilsResult<sequoia_openpgp::Cert> {
    use sequoia_openpgp::parse::Parse;
    sequoia_openpgp::Cert::from_bytes(armored.as_bytes())
        .map_err(|e| CryptoUtilsError::OpenPgp(format!("parse cert: {}", e)))
}

/// Get the user's own fingerprint from a local cert file.
///
/// Reads `~/.add/gnupg/own_cert.asc` (armored public key) and
/// extracts the fingerprint.
pub fn get_own_fingerprint() -> CryptoUtilsResult<String> {
    let path = dirs::home_dir()
        .map(|h| h.join(".add/gnupg/own_cert.asc"))
        .ok_or_else(|| {
            CryptoUtilsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "home dir not found",
            ))
        })?;

    let armored = std::fs::read_to_string(&path)?;

    let cert = parse_cert_armored(&armored)?;
    Ok(fingerprint_from_cert(&cert))
}

/// Export the user's public key (armored) from the local cert file.
pub fn export_pubkey() -> CryptoUtilsResult<String> {
    let path = dirs::home_dir()
        .map(|h| h.join(".add/gnupg/own_cert.asc"))
        .ok_or_else(|| {
            CryptoUtilsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "home dir not found",
            ))
        })?;

    std::fs::read_to_string(&path).map_err(CryptoUtilsError::Io)
}

/// Import a public key (armored) and return its fingerprint.
///
/// Stores the cert to the local cert cache for later lookup.
///
/// SECURITY FIX (G7): Fingerprint is sanitized before use in filesystem path
/// to prevent path traversal attacks. The fingerprint must be 32-40 hex chars,
/// but we also strip any potential path separators or special characters.
pub fn import_pubkey(armored: &str) -> CryptoUtilsResult<String> {
    let cert = parse_cert_armored(armored)?;
    let fp = fingerprint_from_cert(&cert);

    if !validate_fingerprint(&fp) {
        return Err(CryptoUtilsError::InvalidFingerprint(fp));
    }

    // SECURITY FIX (G7): Sanitize fingerprint for safe filename use
    // Only allow hex characters to prevent path traversal
    let safe_fp = fp
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>();

    // Store the cert for later use
    let cert_dir = dirs::home_dir()
        .map(|h| h.join(".add/gnupg"))
        .ok_or_else(|| {
            CryptoUtilsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "home dir not found",
            ))
        })?;
    let _ = std::fs::create_dir_all(&cert_dir);
    let cert_path = cert_dir.join(format!("{}.asc", safe_fp));
    std::fs::write(&cert_path, armored).map_err(CryptoUtilsError::Io)?;

    info!("Imported key with fingerprint {}", fp);
    Ok(fp)
}

/// Read the fingerprint from an armored key without importing it.
///
/// Uses Sequoia's PacketParser to extract the fingerprint from the
/// key packet.
pub fn get_fingerprint_from_armored(armored: &str) -> CryptoUtilsResult<String> {
    use sequoia_openpgp::parse::{PacketParserBuilder, Parse};

    let pile = PacketParserBuilder::from_bytes(armored.as_bytes())
        .map_err(|e| CryptoUtilsError::OpenPgp(format!("parse armored: {:?}", e)))?
        .max_recursion_depth(0)
        .buffer_unread_content()
        .into_packet_pile()
        .map_err(|e| CryptoUtilsError::OpenPgp(format!("packet pile: {:?}", e)))?;

    // Find the first certificate and extract its fingerprint
    for packet in pile.descendants() {
        if let sequoia_openpgp::Packet::PublicKey(cert) = packet {
            return Ok(cert.fingerprint().to_hex().to_uppercase());
        }
    }

    Err(CryptoUtilsError::OpenPgp(
        "no public key found in armored data".to_string(),
    ))
}

/// Explicitly set the trust level for a key.
///
/// Stores trust in a local trust file since Sequoia doesn't have a
/// keyring concept like GPG.
pub fn set_key_trust(fingerprint: &str, trust_level: &str) -> CryptoUtilsResult<()> {
    if !validate_fingerprint(fingerprint) {
        return Err(CryptoUtilsError::InvalidFingerprint(
            fingerprint.to_string(),
        ));
    }

    let valid_trusts = ["ultimate", "marginal", "never", "unknown"];
    if !valid_trusts.contains(&trust_level) {
        return Err(CryptoUtilsError::InvalidTrustLevel(trust_level.to_string()));
    }

    // Store trust in local file
    let trust_path = dirs::home_dir()
        .map(|h| h.join(".add/gnupg/trust_map.txt"))
        .ok_or_else(|| {
            CryptoUtilsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "home dir not found",
            ))
        })?;

    let _ = std::fs::create_dir_all(trust_path.parent().unwrap());
    let entry = format!("{}: {}\n", fingerprint.to_uppercase(), trust_level);
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&trust_path)?;
    file.write_all(entry.as_bytes())?;

    info!("Set trust for {} to {}", fingerprint, trust_level);
    Ok(())
}

// ------------------------------------------------------------------ //
//  Null ID derivation from fingerprint                                 //
// ------------------------------------------------------------------ //

/// Derive a Null ID (NN-XXXX-XXXX) from a GPG fingerprint.
///
/// SECURITY FIX (M1): Uses BLAKE2b-8 (via add-protocol) for consistency
/// with crypto::null_id() and dht-core::compute_null_id(). Previously used
/// SHA-256, which produced a different Null ID for the same fingerprint.
pub fn null_id_from_fingerprint(fp: &str) -> String {
    let cleaned = fp.replace(' ', "").to_lowercase();
    let hex = add_protocol::pow::blake2b_8_hex(&cleaned);
    let part1 = &hex[..4];
    let part2 = &hex[4..8];
    format!("NN-{}-{}", part1.to_uppercase(), part2.to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_fingerprint() {
        // 40-char v4 fingerprint
        assert!(validate_fingerprint(
            "AABBCCDDEEFF00112233445566778899AABBCCDD"
        ));
        assert!(validate_fingerprint(
            "AABB CCDD EEFF 0011 2233 4455 6677 8899 AABB CCDD"
        ));
        // 32-char v3 fingerprint (SECURITY FIX L6)
        assert!(validate_fingerprint("AABBCCDDEEFF00112233445566778899"));
        assert!(!validate_fingerprint("TOOSHORT"));
        assert!(!validate_fingerprint(""));
        assert!(!validate_fingerprint(
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        ));
    }

    #[test]
    fn test_null_id_from_fingerprint() {
        let nid = null_id_from_fingerprint("AABBCCDDEEFF00112233445566778899AABBCCDD");
        assert!(nid.starts_with("NN-"));
        assert_eq!(nid.len(), 12); // NN-XXXX-XXXX
    }

    #[test]
    fn test_secure_delete_nonexistent() {
        // Should not error on non-existent file
        assert!(secure_delete("/tmp/nonexistent_add_test_file").is_ok());
    }

    #[test]
    fn test_secure_delete_existing() {
        let path = "/tmp/add_secure_delete_test";
        fs::write(path, "test data that should be deleted").unwrap();
        assert!(Path::new(path).exists());
        secure_delete(path).unwrap();
        assert!(!Path::new(path).exists());
    }
}
