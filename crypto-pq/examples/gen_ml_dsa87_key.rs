//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
//! Generate ML-DSA-87 keypair for reflector bot

use add_crypto_pq::{generate_keypair, fingerprint_from_verifying_key};
use std::fs;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ml_dsa::KeyExport;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sk, vk) = generate_keypair()?;
    
    // Get fingerprint
    let fp = fingerprint_from_verifying_key(&vk);
    println!("ML-DSA-87 Fingerprint: {}", fp);
    
    // Save private key as raw bytes (base64 encoded)
    let sk_bytes = sk.to_bytes();
    let sk_b64 = BASE64_STANDARD.encode(sk_bytes);
    fs::write("reflector_ml_dsa87_sk.b64", sk_b64)?;
    println!("Private key (base64) saved to reflector_ml_dsa87_sk.b64");
    println!("Fingerprint: {}", fp);
    
    Ok(())
}