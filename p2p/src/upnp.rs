//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// UPnP/IGD port mapping (BitTorrent-style NAT traversal).
//
// Dependency-free: SSDP discovery runs over UDP multicast, SOAP control messages are
// plain HTTP/1.1 POSTs we hand-roll over TcpStream. No external HTTP/XML crates.
//
// Flow: SSDP M-SEARCH -> fetch device description -> locate WAN*Connection service
//       -> AddPortMapping(external -> internal) + GetExternalIPAddress.
//-------------------------------------------------------------------------------

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info, warn};

use crate::P2pError;

const SSDP_ADDR: &str = "239.255.255.250:1900";
const SSDP_MSEARCH: &str = "M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 3\r\n\
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
\r\n";
const SSDP_TIMEOUT: Duration = Duration::from_secs(4);

/// A discovered IGD (Internet Gateway Device) with its WAN connection control URL.
pub struct Igd {
    /// Control URL for the WANIPConnection / WANPPPConnection service.
    control_url: String,
    /// LAN IP of this host (the internal client for the mapping).
    internal_ip: Ipv4Addr,
}

impl Igd {
    /// Discover the first reachable IGD via SSDP and locate its WAN connection service.
    pub async fn discover(internal_ip: Ipv4Addr) -> Result<Self, P2pError> {
        let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| P2pError::Nat(format!("ssdp bind: {e}")))?;
        sock.send_to(SSDP_MSEARCH.as_bytes(), SSDP_ADDR).await.map_err(|e| P2pError::Nat(format!("ssdp send: {e}")))?;

        let mut buf = [0u8; 4096];
        let mut location: Option<String> = None;
        // Collect responses until timeout; grab the first usable LOCATION.
        let deadline = tokio::time::Instant::now() + SSDP_TIMEOUT;
        loop {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            match tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _src))) => {
                    let text = String::from_utf8_lossy(&buf[..n]);
                    if let Some(loc) = header_value(&text, "LOCATION") {
                        location = Some(loc);
                        break;
                    }
                }
                _ => break, // timeout or socket error -> stop collecting
            }
        }

        let location = location.ok_or_else(|| P2pError::Nat("no IGD found via SSDP".into()))?;
        debug!("UPnP: IGD device description at {location}");

        let desc = http_get(&location).await?;
        let control_url = extract_wan_control_url(&desc)
            .ok_or_else(|| P2pError::Nat("no WAN*Connection service in IGD description".into()))?;
        let control_url = resolve_url(&location, &control_url);

        info!("UPnP: found IGD WAN control at {control_url}");
        Ok(Self { control_url, internal_ip })
    }

    /// Map an external TCP port to our internal listener port. Tries the same port
    /// first, then a few random alternatives if the router rejects it.
    /// Returns the external port that was successfully mapped.
    pub async fn add_tcp_mapping(
        &self,
        internal_port: u16,
        lease_secs: u32,
    ) -> Result<u16, P2pError> {
        let candidates: Vec<u16> = {
            let mut v = vec![internal_port];
            for _ in 0..5 {
                v.push(rand::random::<u16>() % 40000 + 20000);
            }
            v
        };
        let mut last_err = None;
        for ext in candidates {
            match self.soap_add_port_mapping("TCP", ext, self.internal_ip, internal_port, lease_secs).await {
                Ok(()) => {
                    info!("UPnP: mapped external {}:{} -> {}:{}", "?", ext, self.internal_ip, internal_port);
                    return Ok(ext);
                }
                Err(e) => {
                    debug!("UPnP: AddPortMapping {} failed: {e}", ext);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| P2pError::Nat("AddPortMapping failed".into())))
    }

    /// Query the router's public (external) IP address.
    pub async fn external_ip(&self) -> Result<Ipv4Addr, P2pError> {
        let body = soap_envelope("GetExternalIPAddress", "");
        let resp = self.soap_call(&body).await?;
        extract_tag(&resp, "NewExternalIPAddress")
            .and_then(|s| s.parse::<Ipv4Addr>().ok())
            .ok_or_else(|| P2pError::Nat("no NewExternalIPAddress in IGD response".into()))
    }

    /// Best-effort removal of a mapping (call on shutdown). Errors are non-fatal.
    pub async fn remove_tcp_mapping(&self, external_port: u16) {
        if let Err(e) = self.soap_delete_port_mapping("TCP", external_port).await {
            warn!("UPnP: failed to remove port mapping {}: {e}", external_port);
        }
    }

    async fn soap_add_port_mapping(
        &self,
        proto: &str,
        ext_port: u16,
        int_ip: Ipv4Addr,
        int_port: u16,
        lease: u32,
    ) -> Result<(), P2pError> {
        let args = format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{ext_port}</NewExternalPort>\
             <NewProtocol>{proto}</NewProtocol>\
             <NewInternalPort>{int_port}</NewInternalPort>\
             <NewInternalClient>{int_ip}</NewInternalClient>\
             <NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>Add P2P</NewPortMappingDescription>\
             <NewLeaseDuration>{lease}</NewLeaseDuration>"
        );
        let body = soap_envelope("AddPortMapping", &args);
        let resp = self.soap_call(&body).await?;
        if resp.contains("AddPortMappingResponse") && !resp.contains("<errorCode>") {
            Ok(())
        } else {
            Err(P2pError::Nat(format!("AddPortMapping rejected: {resp}")))
        }
    }

    async fn soap_delete_port_mapping(&self, proto: &str, ext_port: u16) -> Result<(), P2pError> {
        let args = format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{ext_port}</NewExternalPort>\
             <NewProtocol>{proto}</NewProtocol>"
        );
        let body = soap_envelope("DeletePortMapping", &args);
        let resp = self.soap_call(&body).await?;
        if resp.contains("DeletePortMappingResponse") && !resp.contains("<errorCode>") {
            Ok(())
        } else {
            Err(P2pError::Nat(format!("DeletePortMapping rejected: {resp}")))
        }
    }

    /// POST a SOAP action to the IGD control URL and return the response body.
    async fn soap_call(&self, body: &str) -> Result<String, P2pError> {
        let url = &self.control_url;
        let req = format!(
            "POST {path} HTTP/1.1\r\n\
             HOST: {host}\r\n\
             CONTENT-TYPE: text/xml; charset=\"utf-8\"\r\n\
             SOAPACTION: \"urn:schemas-upnp-org:service:WANIPConnection:1#{action}\"\r\n\
             CONTENT-LENGTH: {len}\r\n\
             CONNECTION: close\r\n\
             \r\n\
             {body}",
            path = url_path(url),
            host = url_host(url),
            len = body.len(),
            action = soap_action(body),
            body = body,
        );
        let resp = http_post(url, &req).await?;
        Ok(resp)
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn soap_action(body: &str) -> &str {
    // The action name is the first <u:Name ...> tag.
    let start = body.find("<u:").map(|i| i + 3).unwrap_or(0);
    let end = body[start..].find(' ').map(|i| start + i).unwrap_or(body.len());
    &body[start..end]
}

fn soap_envelope(action: &str, args: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\r\n\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n\
         <s:Body>\r\n\
         <u:{action} xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\r\n\
         {args}\r\n\
         </u:{action}>\r\n\
         </s:Body>\r\n\
         </s:Envelope>"
    )
}

/// Minimal HTTP/1.1 GET (used for SSDP device descriptions).
async fn http_get(url: &str) -> Result<String, P2pError> {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHOST: {host}\r\nCONNECTION: close\r\n\r\n",
        path = url_path(url),
        host = url_host(url),
    );
    http_request(url, &req).await
}

async fn http_post(url: &str, req: &str) -> Result<String, P2pError> {
    http_request(url, req).await
}

/// Open a TCP connection to `url` (http://host:port) and exchange `req`/`resp`.
async fn http_request(url: &str, req: &str) -> Result<String, P2pError> {
    let host = url_host(url);
    let port = url_port(url);
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| P2pError::Nat(format!("bad IGD url {url}: {e}")))?;

    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .map_err(|_| P2pError::Nat(format!("IGD connect timeout {addr}")))?
        .map_err(|e| P2pError::Nat(format!("IGD connect {addr}: {e}")))?;

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| P2pError::Nat(format!("IGD write: {e}")))?;

    let mut resp = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut resp)).await;
    let text = String::from_utf8_lossy(&resp).to_string();
    // Strip chunked-encoding framing: we only care about the body after the blank line.
    Ok(text)
}

fn url_host(url: &str) -> String {
    let without_scheme = url.trim_start_matches("http://").trim_start_matches("https://");
    without_scheme.split('/').next().unwrap_or("").split(':').next().unwrap_or("").to_string()
}

fn url_port(url: &str) -> u16 {
    let without_scheme = url.trim_start_matches("http://").trim_start_matches("https://");
    let authority = without_scheme.split('/').next().unwrap_or("");
    if let Some(idx) = authority.rfind(':') {
        authority[idx + 1..].parse().unwrap_or(80)
    } else {
        80
    }
}

fn url_path(url: &str) -> String {
    let without_scheme = url.trim_start_matches("http://").trim_start_matches("https://");
    let authority = without_scheme.split('/').next().unwrap_or("");
    let path = &without_scheme[authority.len()..];
    if path.is_empty() { "/".to_string() } else { path.to_string() }
}

fn resolve_url(base: &str, relative: &str) -> String {
    if relative.starts_with("http://") || relative.starts_with("https://") {
        return relative.to_string();
    }
    // Resolve against base authority.
    let base_no_scheme = base.trim_start_matches("http://").trim_start_matches("https://");
    let authority = base_no_scheme.split('/').next().unwrap_or("");
    format!("http://{authority}{}", if relative.starts_with('/') { relative.to_string() } else { format!("/{relative}") })
}

/// Extract the first WANIPConnection / WANPPPConnection controlURL from a device
/// description document. We pair the service type with the controlURL that follows it.
fn extract_wan_control_url(desc: &str) -> Option<String> {
    let services = ["WANIPConnection", "WANPPPConnection"];
    for svc in services {
        if let Some(idx) = desc.find(svc) {
            // Walk forward from this serviceType for the next controlURL element.
            let after = &desc[idx..];
            if let Some(cu) = extract_tag(after, "controlURL") {
                return Some(cu);
            }
        }
    }
    None
}

/// Case-insensitive header/key lookup: return the trimmed value after "KEY:".
fn header_value(text: &str, key: &str) -> Option<String> {
    let key_lower = key.to_ascii_lowercase();
    for line in text.lines() {
        let t = line.trim_start();
        if t.to_ascii_lowercase().starts_with(&format!("{key_lower}:")) {
            let v = t[key.len() + 1..].trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Extract the content of the first <tag>...</tag> occurrence.
fn extract_tag(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    Some(text[start..end].trim().to_string())
}
