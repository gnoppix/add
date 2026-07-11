//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// OpenPGP signing utilities using Sequoia (in-process, no GPG binary required).
//
// SECURITY FIX (C3): P2P messages (hello-ack, p2p-message, p2p-ack) must be
// signed to prevent MITM injection attacks. This module provides detached
// signature creation and verification using the Sequoia OpenPGP library.
//-------------------------------------------------------------------------------

use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::crypto::KeyPair;
use sequoia_openpgp::packet::prelude::*;
use sequoia_openpgp::parse::{Parse, PacketParserBuilder};
use sequoia_openpgp::serialize::stream::{Armorer, Message, Signer};
use sequoia_openpgp::serialize::Serialize;
use std::io::Write;
use std::time::SystemTime;

/// Sign data with a detached OpenPGP signature using Sequoia.
///
/// Uses the certificate's primary secret key for signing.
/// Returns ASCII-armored detached signature.
pub fn sign_detached(data: &str, cert: &Cert) -> Result<String, String> {
    let ka = cert.keys().next().ok_or("no key found in certificate")?;

    let keypair = ka
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|e| format!("secret key unavailable: {}", e))?
        .into_keypair()
        .map_err(|e| format!("keypair conversion: {}", e))?;

    let mut sig_buf = Vec::new();
    {
        let message = Message::new(&mut sig_buf);
        let message = Armorer::new(message)
            .kind(sequoia_openpgp::armor::Kind::Signature)
            .build()
            .map_err(|e| format!("armorer build: {}", e))?;
        let mut message = Signer::new(message, keypair)
            .map_err(|e| format!("signer new: {}", e))?
            .detached()
            .creation_time(SystemTime::now())
            .build()
            .map_err(|e| format!("signer build: {}", e))?;

        message
            .write_all(data.as_bytes())
            .map_err(|e| format!("sign data write: {}", e))?;
        // finalize_one() pops the Signer, calling emit_signatures() which
        // writes the signature to the underlying Armorer.
        let message = message
            .finalize_one()
            .map_err(|e| format!("sign finalize_one: {}", e))?
            .ok_or("sign finalize_one returned None")?;
        // Finalize the Armorer (writes armor footer).
        message
            .finalize()
            .map_err(|e| format!("armorer finalize: {}", e))?;
    }
    String::from_utf8(sig_buf).map_err(|e| format!("sig UTF-8: {}", e))
}

/// Verify a detached OpenPGP signature.
///
/// Verifies that `data` was signed by the key associated with `cert`.
/// Returns true if the signature is valid and made by the certificate holder.
pub fn verify_detached(sig_armored: &str, data: &str, cert: &Cert) -> Result<bool, String> {
    let pile = PacketParserBuilder::from_bytes(sig_armored.as_bytes())
        .map_err(|e| format!("parse signature: {}", e))?
        .max_recursion_depth(0)
        .buffer_unread_content()
        .into_packet_pile()
        .map_err(|e| format!("parse signature pile: {}", e))?;

    let signing_key = cert
        .keys()
        .next()
        .map(|ka| ka.key())
        .ok_or("no key found in certificate")?;

    for packet in pile.descendants() {
        if let Packet::Signature(sig) = packet {
            let algo = sig.hash_algo();
            let sig_key = cert.keys().next().unwrap().key();
            let version = sig_key.version();
            let mut hash_ctx = algo
                .context()
                .map_err(|e| format!("hash context: {}", e))?
                .for_signature(version);
            hash_ctx.update(data.as_bytes());
            match sig.verify_hash(signing_key, hash_ctx) {
                Ok(()) => return Ok(true),
                Err(_) => continue,
            }
        }
    }

    Ok(false)
}

/// Parse a certificate from binary bytes.
pub fn cert_from_bytes(bytes: &[u8]) -> Result<Cert, String> {
    Cert::from_bytes(bytes).map_err(|e| format!("parse cert: {}", e))
}

/// Serialize a certificate to binary bytes.
pub fn cert_to_bytes(cert: &Cert) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    cert.as_tsk()
        .serialize(&mut buf)
        .map_err(|e| format!("serialize cert: {}", e))?;
    Ok(buf)
}

/// Get the fingerprint from a certificate.
pub fn cert_fingerprint(cert: &Cert) -> String {
    cert.fingerprint().to_hex()
}

/// Alias: Get the fingerprint from a certificate (same as cert_fingerprint).
pub fn fingerprint_from_cert(cert: &Cert) -> String {
    cert_fingerprint(cert)
}

/// Parse a certificate from armored string.
pub fn cert_from_armored(armored: &str) -> Result<Cert, String> {
    Cert::from_bytes(armored.as_bytes()).map_err(|e| format!("parse armored cert: {}", e))
}

/// Generate a new OpenPGP keypair (Cv25519 EdDSA).
///
/// Returns (cert, keypair) where cert is the generated certificate and
/// keypair is the secret key for signing.
pub fn generate_keypair(user_id: &str) -> Result<(Cert, KeyPair), String> {
    let (cert, _) = CertBuilder::general_purpose(Some(user_id))
        .set_cipher_suite(sequoia_openpgp::cert::CipherSuite::Cv25519)
        .set_creation_time(SystemTime::now())
        .generate()
        .map_err(|e| format!("key generation: {}", e))?;

    let keypair = cert
        .keys()
        .next()
        .map(|ka| ka.key())
        .ok_or("no secret key after generation")?
        .clone()
        .parts_into_secret()
        .map_err(|e| format!("secret key unavailable: {}", e))?
        .into_keypair()
        .map_err(|e| format!("keypair conversion: {}", e))?;

    Ok((cert, keypair))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let (cert, _) = generate_keypair("test <test@example.com>").unwrap();
        let data = "Hello, Add world!";

        let sig = sign_detached(data, &cert).expect("sign");
        assert!(sig.contains("BEGIN PGP SIGNATURE"));

        let valid = verify_detached(&sig, data, &cert).expect("verify");
        assert!(valid, "signature should be valid");
    }

    #[test]
    fn test_verify_wrong_data() {
        let (cert, _) = generate_keypair("test <test@example.com>").unwrap();
        let sig = sign_detached("original data", &cert).unwrap();

        // SECURITY FIX (C1): verify_detached must reject signatures made over
        // different data. This prevents signature replay attacks.
        let valid = verify_detached(&sig, "different data", &cert).unwrap();
        assert!(!valid, "signature over different data must NOT verify");
    }

    #[test]
    fn test_cert_from_bytes() {
        let (cert, _) = generate_keypair("test <test@example.com>").unwrap();
        let bytes = cert_to_bytes(&cert).unwrap();
        let parsed = cert_from_bytes(&bytes).unwrap();
        assert_eq!(cert_fingerprint(&cert), cert_fingerprint(&parsed));
    }

    #[test]
    fn test_cert_fingerprint() {
        let (cert, _) = generate_keypair("test <test@example.com>").unwrap();
        let fp = cert_fingerprint(&cert);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
