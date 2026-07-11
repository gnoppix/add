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

    if pattern.starts_with("*.") {
        let base = &pattern[2..];
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
        if ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for name in &san.general_names {
                    if let GeneralName::DNSName(name_str) = name {
                        subject_alt_names.push(name_str.to_string());
                    }
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

/// Check if the certificate issuer is a known trusted CA.
/// Check if the certificate issuer is a known trusted CA.
pub fn cert_issuer_is_trusted(cert_info: &CertInfo) -> bool {
    cert_issuer_name_is_trusted(cert_info)
}

/// Check if the certificate issuer name matches known trusted CAs.
pub fn cert_issuer_name_is_trusted(cert_info: &CertInfo) -> bool {
    let cn = cert_info.issuer_cn.as_deref().unwrap_or("").to_lowercase();
    let org = cert_info.issuer_org.as_deref().unwrap_or("").to_lowercase();

    if org.contains("let's encrypt") || cn.contains("let's encrypt") {
        return true;
    }

    if org.contains("isrg") || org.contains("internet security") {
        return true;
    }

    warn!(
        "bootstrap cert issuer NOT TRUSTED (CN={}, org={}) -- must chain to Let's Encrypt",
        cert_info.issuer_cn.as_deref().unwrap_or("?"),
        cert_info.issuer_org.as_deref().unwrap_or("?")
    );
    false
}

// ------------------------------------------------------------------ //
//  Main verification function                                        //
// ------------------------------------------------------------------ //

/// Verify the TLS certificate of a bootstrap server.
///
/// Performs a TLS handshake to extract the peer certificate fingerprint
/// and validity dates, then checks it against pinned values.
///
/// SECURITY: Also verifies the certificate belongs to a trusted domain
/// (*.gnoppix.org or *.gnoppix.com) and chains to a trusted CA (Let's Encrypt).
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

    // SECURITY: Verify the cert chains to a trusted CA (Let's Encrypt)
    if !cert_issuer_is_trusted(&cert_info) {
        warn!(
            "bootstrap {} cert CA NOT TRUSTED (issuer={:?}) -- rejecting",
            seed_url, cert_info.issuer_cn
        );
        return false;
    }

    // Check against pinned values
    bootstrap_pin_check(seed_url, &cert_fp, &cert_info.not_before, &cert_info.not_after)
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

    #[test]
    fn test_cert_issuer_is_trusted_logic() {
        let lets_encrypt = CertInfo {
            subject_alt_names: vec![],
            subject_cn: None,
            issuer_cn: Some("Let's Encrypt Authority X3".to_string()),
            issuer_org: Some("Let's Encrypt".to_string()),
            not_before: String::new(),
            not_after: String::new(),
        };
        assert!(cert_issuer_is_trusted(&lets_encrypt));

        let isrg = CertInfo {
            subject_alt_names: vec![],
            subject_cn: None,
            issuer_cn: Some("ISRG Root X1".to_string()),
            issuer_org: Some("Internet Security Research Group".to_string()),
            not_before: String::new(),
            not_after: String::new(),
        };
        assert!(cert_issuer_is_trusted(&isrg));

        let evil = CertInfo {
            subject_alt_names: vec![],
            subject_cn: None,
            issuer_cn: Some("Evil CA".to_string()),
            issuer_org: Some("Evil Corp".to_string()),
            not_before: String::new(),
            not_after: String::new(),
        };
        assert!(!cert_issuer_is_trusted(&evil));
    }
}
