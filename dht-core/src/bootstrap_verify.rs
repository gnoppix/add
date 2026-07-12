//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// Bootstrap TLS certificate verification
//-------------------------------------------------------------------------------

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use tracing::warn;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::*;

use crate::pin_cache::bootstrap_pin_check;

// ------------------------------------------------------------------ //
//  Trusted domains                                                   //
// ------------------------------------------------------------------ //

/// SECURITY FIX (L5): Removed fake TRUSTED_CA_FINGERPRINTS placeholder
/// that contained a non-existent fingerprint with a sequential hex pattern.
/// CA pinning is handled via the TOFU bootstrap_pin_cache.json mechanism,
/// not a hardcoded list of CA fingerprints.
const TRUSTED_DOMAINS: &[&str] = &["*.gnoppix.org", "*.gnoppix.com"];

// ------------------------------------------------------------------ //
//  Domain matching                                                   //
// ------------------------------------------------------------------ //

/// Check if a domain matches a wildcard pattern (e.g., *.gnoppix.org).
pub fn domain_matches(cert_domain: &str, pattern: &str) -> bool {
    let cert_domain = cert_domain.to_lowercase();
    let pattern = pattern.to_lowercase();

    if let Some(base) = pattern.strip_prefix("*.") {
        cert_domain == base || cert_domain.ends_with(&format!(".{}", base))
    } else {
        cert_domain == pattern
    }
}

// ------------------------------------------------------------------ //
//  Certificate info extraction                                       //
// ------------------------------------------------------------------ //

/// Certificate information extracted from TLS cert.
/// SECURITY FIX (H1): Made fields pub to fix future Rust edition warning.
/// The struct is passed to public functions but fields were private.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub subject_alt_names: Vec<String>,
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub issuer_org: Option<String>,
    pub not_before: String,
    pub not_after: String,
}

fn extract_cert_info(cert_der: &[u8]) -> Result<CertInfo, String> {
    let (_, cert) = parse_x509_certificate(cert_der)
        .map_err(|e| format!("failed to parse certificate: {:?}", e))?;

    let mut subject_alt_names = Vec::new();
    for ext in cert.extensions() {
        if ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME
            && let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension()
        {
            for name in &san.general_names {
                if let GeneralName::DNSName(name_str) = name {
                    subject_alt_names.push(name_str.to_string());
                }
            }
        }
    }

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());

    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());

    let issuer_org = cert
        .issuer()
        .iter_organization()
        .next()
        .and_then(|o| o.as_str().ok())
        .map(|s| s.to_string());

    let not_before = cert.validity().not_before.to_string();
    let not_after = cert.validity().not_after.to_string();

    Ok(CertInfo {
        subject_alt_names,
        subject_cn,
        issuer_cn,
        issuer_org,
        not_before,
        not_after,
    })
}

// ------------------------------------------------------------------ //
//  Trust checks                                                      //
// ------------------------------------------------------------------ //

/// Check if the certificate has a SAN or CN matching TRUSTED_DOMAINS.
pub fn cert_has_trusted_domain(cert_info: &CertInfo) -> bool {
    for san in &cert_info.subject_alt_names {
        for pattern in TRUSTED_DOMAINS {
            if domain_matches(san, pattern) {
                return true;
            }
        }
    }

    if let Some(ref cn) = cert_info.subject_cn {
        for pattern in TRUSTED_DOMAINS {
            if domain_matches(cn, pattern) {
                return true;
            }
        }
    }

    false
}

// ------------------------------------------------------------------ //
//  Main verification function                                        //
// ------------------------------------------------------------------ //

/// Verify the TLS certificate of a bootstrap server.
///
/// Performs a TLS handshake with a WebPKI verifier (chain + expiry validated by
/// rustls against the native root store) and checks the certificate against the
/// pinned fingerprint (TOFU, with an explicit warning on first contact and a
/// hard-fail on pin mismatch).
///
/// SECURITY FIX (H3): dropped the redundant issuer-substring ("Let's Encrypt")
/// check. WebPKI already validates the chain; the substring check added no
/// security and created a false sense of CA pinning. Trust now rests solely on
/// WebPKI chain validation + the TOFU fingerprint pin.
pub fn verify_bootstrap_cert(seed_url: &str) -> bool {
    let host_port = seed_url
        .strip_prefix("wss://")
        .or_else(|| seed_url.strip_prefix("https://"))
        .unwrap_or(seed_url);

    let (host, port) = if let Some(idx) = host_port.rfind(':') {
        let h = &host_port[..idx];
        let p: u16 = host_port[idx + 1..].parse().unwrap_or(443);
        (h, p)
    } else {
        (host_port, 443)
    };

    // Build TLS config with WebPKI verifier using native root store + ring
    let root_store = {
        let mut store = rustls::RootCertStore::empty();
        let certs = rustls_native_certs::load_native_certs();
        store.add_parsable_certificates(certs.certs);
        store
    };
    let provider = rustls::crypto::ring::default_provider();
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(root_store),
        Arc::new(provider),
    )
    .build()
    .expect("webpki verifier build failed");
    let config = ClientConfig::builder()
        .with_webpki_verifier(verifier)
        .with_no_client_auth();

    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(name) => name,
        Err(_) => {
            warn!("bootstrap {} has invalid hostname", seed_url);
            return false;
        }
    };

    let mut conn = match rustls::ClientConnection::new(Arc::new(config), server_name) {
        Ok(c) => c,
        Err(e) => {
            warn!("bootstrap {} TLS setup failed: {}", seed_url, e);
            return false;
        }
    };

    let addr = SocketAddr::new(
        host.parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port,
    );
    let sock = match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(e) => {
            warn!("bootstrap {} connection failed: {}", seed_url, e);
            return false;
        }
    };
    let mut sock = sock.try_clone().expect("tcp clone failed");

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    // Trigger the handshake by reading
    let mut buf = [0u8; 1];
    if let Err(e) = tls.read(&mut buf) {
        warn!("bootstrap {} TLS handshake failed: {}", seed_url, e);
        return false;
    }

    // Extract peer certificates from the connection
    let cert = match tls.conn.peer_certificates() {
        Some(certs) if !certs.is_empty() => certs[0].clone(),
        _ => {
            warn!("bootstrap {} did not present a certificate", seed_url);
            return false;
        }
    };

    let der_cert = cert.as_ref();

    // Compute fingerprint
    let mut hasher = Sha256::new();
    hasher.update(der_cert);
    let cert_fp = format!("{:x}", hasher.finalize());

    // Parse certificate info
    let cert_info = match extract_cert_info(der_cert) {
        Ok(info) => info,
        Err(e) => {
            warn!("bootstrap {} cert parse failed: {}", seed_url, e);
            return false;
        }
    };

    // SECURITY: Verify the cert belongs to a trusted domain
    if !cert_has_trusted_domain(&cert_info) {
        warn!(
            "bootstrap {} cert domain NOT TRUSTED (SAN={:?} CN={:?}) -- rejecting",
            seed_url, cert_info.subject_alt_names, cert_info.subject_cn
        );
        return false;
    }

    // NOTE (H3): The redundant issuer-substring ("Let's Encrypt") check was
    // removed. Chain validation is performed by the WebPKI verifier above; any
    // self-signed or unchained cert already failed the handshake. Trust rests on
    // WebPKI + the TOFU fingerprint pin below (which hard-fails on mismatch).

    // Check against pinned values
    bootstrap_pin_check(
        seed_url,
        &cert_fp,
        &cert_info.not_before,
        &cert_info.not_after,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_matches() {
        assert!(domain_matches("bootstrap.gnoppix.org", "*.gnoppix.org"));
        assert!(domain_matches("sub.gnoppix.org", "*.gnoppix.org"));
        assert!(!domain_matches("evil.com", "*.gnoppix.org"));
        assert!(domain_matches("gnoppix.org", "*.gnoppix.org"));
    }

    #[test]
    fn test_cert_has_trusted_domain_logic() {
        let info = CertInfo {
            subject_alt_names: vec!["bootstrap.gnoppix.org".to_string()],
            subject_cn: None,
            issuer_cn: None,
            issuer_org: None,
            not_before: String::new(),
            not_after: String::new(),
        };
        assert!(cert_has_trusted_domain(&info));

        let info_bad = CertInfo {
            subject_alt_names: vec!["evil.com".to_string()],
            subject_cn: None,
            issuer_cn: None,
            issuer_org: None,
            not_before: String::new(),
            not_after: String::new(),
        };
        assert!(!cert_has_trusted_domain(&info_bad));
    }
}
