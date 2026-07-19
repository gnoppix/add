//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// Transport layer (direct + SOCKS5/Tor).
//-------------------------------------------------------------------------------

use std::time::Duration;

use futures::{SinkExt as _, StreamExt as _};
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;
use tracing::warn;
use url::Url;

use add_protocol::envelope::WireEnvelope;

use crate::P2pError;

/// WebSocket connection handle (direct or through SOCKS5 proxy).
pub type WebSocketConn = tokio_tungstenite::WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Transport configuration.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub use_tor: bool,
    pub tor_socks_host: String,
    pub tor_socks_port: u16,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            use_tor: false,
            tor_socks_host: "127.0.0.1".to_string(),
            tor_socks_port: 9050,
        }
    }
}

impl TransportConfig {
    pub fn tor_socks_url(&self) -> String {
        format!("socks5://{}:{}", self.tor_socks_host, self.tor_socks_port)
    }
}

/// Transport manager for P2P connections.
#[derive(Debug, Clone)]
pub struct TransportManager {
    config: TransportConfig,
}

impl TransportManager {
    pub fn new(config: TransportConfig) -> Self {
        Self { config }
    }

    pub fn is_tor_enabled(&self) -> bool {
        self.config.use_tor
    }

    /// Connect a WebSocket, routing through Tor SOCKS5 if enabled.
    pub async fn connect(&self, uri: &str, timeout_secs: u64) -> Result<WebSocketConn, P2pError> {
        if self.config.use_tor {
            self.connect_through_tor(uri, timeout_secs).await
        } else {
            self.connect_direct(uri, timeout_secs).await
        }
    }

    async fn connect_direct(
        &self,
        uri: &str,
        timeout_secs: u64,
    ) -> Result<WebSocketConn, P2pError> {
        let url = Url::parse(uri).map_err(|e| P2pError::InvalidAddress(e.to_string()))?;

        match url.scheme() {
            "ws" => {
                // Plaintext WebSocket (unchanged)
                let result = tokio::time::timeout(
                    Duration::from_secs(timeout_secs),
                    tokio_tungstenite::connect_async(uri),
                )
                .await;

                match result {
                    Ok(Ok((ws, _))) => Ok(ws),
                    Ok(Err(e)) => Err(P2pError::Connection(e.to_string())),
                    Err(_) => Err(P2pError::Timeout),
                }
            }
            "wss" => {
                // TLS WebSocket — tokio-tungstenite handles this natively
                // when the "rustls-tls-native-roots" feature is enabled.
                let result = tokio::time::timeout(
                    Duration::from_secs(timeout_secs),
                    tokio_tungstenite::connect_async(uri),
                )
                .await;

                match result {
                    Ok(Ok((ws, _))) => Ok(ws),
                    Ok(Err(e)) => Err(P2pError::Connection(e.to_string())),
                    Err(_) => Err(P2pError::Timeout),
                }
            }
            other => Err(P2pError::InvalidAddress(format!(
                "unsupported scheme: {}",
                other
            ))),
        }
    }

    async fn connect_through_tor(
        &self,
        uri: &str,
        timeout_secs: u64,
    ) -> Result<WebSocketConn, P2pError> {
        let url = Url::parse(uri).map_err(|e| P2pError::InvalidAddress(e.to_string()))?;
        let host = url.host_str().unwrap_or("127.0.0.1");
        let port = url.port().unwrap_or(443);

        // Connect to SOCKS5 proxy
        let stream = tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            TcpStream::connect(format!(
                "{}:{}",
                self.config.tor_socks_host, self.config.tor_socks_port
            )),
        )
        .await
        .map_err(|_| P2pError::Timeout)?
        .map_err(|e| P2pError::Connection(format!("SOCKS5 connect failed: {}", e)))?;

        // SOCKS5 handshake then WebSocket upgrade
        Self::socks5_handshake(stream, host, port, timeout_secs).await
    }

    async fn socks5_handshake(
        mut stream: TcpStream,
        host: &str,
        port: u16,
        timeout_secs: u64,
    ) -> Result<WebSocketConn, P2pError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Phase 1: greeting (no auth)
        stream
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .map_err(|e| P2pError::Connection(format!("SOCKS5 write greeting: {}", e)))?;

        let mut resp = [0u8; 2];
        tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            stream.read_exact(&mut resp),
        )
        .await
        .map_err(|_| P2pError::Timeout)?
        .map_err(|e| P2pError::Connection(format!("SOCKS5 read greeting: {}", e)))?;

        if resp[0] != 0x05 || resp[1] != 0x00 {
            return Err(P2pError::Connection(
                "SOCKS5 auth method rejected".to_string(),
            ));
        }

        // Phase 2: CONNECT request (ATYP=0x03 domain)
        let mut req = vec![0x05, 0x01, 0x00, 0x03];
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
        req.push((port >> 8) as u8);
        req.push((port & 0xFF) as u8);

        stream
            .write_all(&req)
            .await
            .map_err(|e| P2pError::Connection(format!("SOCKS5 write request: {}", e)))?;

        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(timeout_secs), stream.read(&mut buf))
            .await
            .map_err(|_| P2pError::Timeout)?
            .map_err(|e| P2pError::Connection(format!("SOCKS5 read response: {}", e)))?;

        if n < 10 || buf[1] != 0x00 {
            return Err(P2pError::Connection(format!(
                "SOCKS5 connect failed with REP={}",
                if n > 1 { buf[1] } else { 0xFF }
            )));
        }

        // Wrap in MaybeTlsStream (no TLS for SOCKS5 tunnel)
        let tls_stream = MaybeTlsStream::Plain(stream);

        // WebSocket handshake over the established tunnel
        let ws = tokio_tungstenite::client_async(uri_dummy(host, port), tls_stream).await;

        match ws {
            Ok((ws_stream, _)) => Ok(ws_stream),
            Err(e) => Err(P2pError::Connection(format!(
                "WebSocket handshake failed: {}",
                e
            ))),
        }
    }

    /// Build a URI for advertising in the DHT.
    pub fn get_peer_uri(&self, host: &str, port: u16) -> String {
        format!("wss://{}:{}", host, port)
    }
}

/// Dummy URL for use after SOCKS5 tunnel is established.
fn uri_dummy(host: &str, port: u16) -> String {
    format!("wss://{}:{}", host, port)
}

/// Check if an address string is a .onion address.
pub fn is_onion_address(addr: &str) -> bool {
    addr.contains(".onion")
}

/// Normalize a peer address for DHT storage.
pub fn normalize_peer_address(addr: &str) -> String {
    if addr.is_empty() {
        return addr.to_string();
    }
    if is_onion_address(addr) {
        let onion_part = addr.split(':').next().unwrap_or(addr);
        if onion_part.ends_with(".onion") && onion_part.len() == 62 {
            return addr.to_string();
        }
        warn!("Malformed .onion address: {}", addr);
    }
    addr.to_string()
}

/// Send an envelope over a WebSocket connection.
pub async fn send_envelope(ws: &mut WebSocketConn, env: &WireEnvelope) -> Result<(), P2pError> {
    let json = env
        .to_json()
        .map_err(|e| P2pError::Serialization(e.to_string()))?;
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
    ))
    .await
    .map_err(|e| P2pError::Connection(e.to_string()))?;
    Ok(())
}

/// Receive an envelope from a WebSocket connection with timeout.
pub async fn recv_envelope(
    ws: &mut WebSocketConn,
    timeout_secs: u64,
) -> Result<WireEnvelope, P2pError> {
    let msg = tokio::time::timeout(Duration::from_secs(timeout_secs), ws.next())
        .await
        .map_err(|_| P2pError::Timeout)?
        .ok_or_else(|| P2pError::Connection("connection closed".to_string()))?;

    match msg {
        Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
            WireEnvelope::from_json(&text).map_err(|e| P2pError::Serialization(e.to_string()))
        }
        Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => {
            Err(P2pError::Connection("connection closed".to_string()))
        }
        Err(e) => Err(P2pError::Connection(e.to_string())),
        _ => Err(P2pError::Connection("unexpected message type".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_onion_address() {
        assert!(is_onion_address("abc...xyz.onion:9001"));
        assert!(!is_onion_address("1.2.3.4:9001"));
        assert!(!is_onion_address("example.com:9001"));
    }

    #[test]
    fn test_normalize_peer_address() {
        assert_eq!(normalize_peer_address(""), "");
        assert_eq!(
            normalize_peer_address("wss://abc...xyz.onion:9001"),
            "wss://abc...xyz.onion:9001"
        );
    }
}
