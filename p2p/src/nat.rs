//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// NAT traversal (STUN + UDP hole punching).
//-------------------------------------------------------------------------------

use std::net::SocketAddr;

use rand::Rng;
use tracing::{info, debug};

use crate::P2pError;

/// Default STUN servers for NAT traversal.
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun.stunprotocol.org:3478",
];

/// Timeout for STUN requests (seconds).
const STUN_TIMEOUT: u64 = 5;

/// Result of a STUN query.
#[derive(Debug, Clone)]
pub struct StunResult {
    pub public_ip: String,
    pub public_port: u16,
}

/// NAT type detection result.
#[derive(Debug, Clone, PartialEq)]
pub enum NatType {
    /// Full cone NAT — any external host can send to the mapped address.
    FullCone,
    /// Restricted cone NAT — only previously contacted hosts can send.
    RestrictedCone,
    /// Port-restricted cone NAT — only previously contacted host:port can send.
    PortRestrictedCone,
    /// Symmetric NAT — different mapping for each destination.
    Symmetric,
    /// No NAT — directly reachable.
    Open,
    /// Unknown / could not be determined.
    Unknown,
}

/// NAT traversal manager.
#[derive(Debug)]
pub struct NatManager {
    stun_servers: Vec<String>,
    nat_type: NatType,
}

impl NatManager {
    pub fn new() -> Self {
        Self {
            stun_servers: STUN_SERVERS.iter().map(|s| s.to_string()).collect(),
            nat_type: NatType::Unknown,
        }
    }

    pub fn with_servers(servers: &[String]) -> Self {
        Self {
            stun_servers: servers.to_vec(),
            nat_type: NatType::Unknown,
        }
    }

    /// Detect the public address using STUN.
    /// Returns the public IP and port.
    pub async fn discover_public_address(&self) -> Result<StunResult, P2pError> {
        // Try each STUN server
        for server in &self.stun_servers {
            match self.query_stun(server).await {
                Ok(result) => {
                    info!(
                        "STUN result from {}: {}:{}",
                        server, result.public_ip, result.public_port
                    );
                    return Ok(result);
                }
                Err(e) => {
                    debug!("STUN query to {} failed: {}", server, e);
                }
            }
        }
        Err(P2pError::Nat(
            "All STUN servers unreachable".to_string(),
        ))
    }

    /// Query a single STUN server.
    async fn query_stun(&self, server: &str) -> Result<StunResult, P2pError> {
        // Build a STUN Binding Request (RFC 5389)
        // Header: 2-byte type (0x0001 = Binding Request), 2-byte length (0), 4-byte magic cookie, 12-byte transaction ID
        let mut request = vec![0u8; 20];
        request[0] = 0x00;
        request[1] = 0x01; // Binding Request
        request[2] = 0x00;
        request[3] = 0x00; // length = 0 (no attributes)
        request[4] = 0x21;
        request[5] = 0x12;
        request[6] = 0xA4;
        request[7] = 0x42; // magic cookie
        // Transaction ID (12 random bytes) — scoped so the !Send ThreadRng
        // is dropped before any .await below (keeps the future Send for spawn).
        {
            let mut rng = rand::thread_rng();
            for i in 8..20 {
                request[i] = rng.r#gen();
            }
        }

        // Send via UDP
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| P2pError::Nat(format!("UDP bind: {}", e)))?;

        socket
            .connect(server)
            .await
            .map_err(|e| P2pError::Nat(format!("STUN connect: {}", e)))?;

        socket
            .send(&request)
            .await
            .map_err(|e| P2pError::Nat(format!("STUN send: {}", e)))?;

        let mut buf = [0u8; 512];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(STUN_TIMEOUT),
            socket.recv(&mut buf),
        )
        .await
        .map_err(|_| P2pError::Timeout)?
        .map_err(|e| P2pError::Nat(format!("STUN recv: {}", e)))?;

        if n < 20 {
            return Err(P2pError::Nat("STUN response too short".to_string()));
        }

        // Parse response — look for XOR-MAPPED-ADDRESS attribute (0x0020)
        let response = &buf[..n];
        if response[0] != 0x01 || response[1] != 0x01 {
            return Err(P2pError::Nat("Not a STUN success response".to_string()));
        }

        // Scan attributes (after 20-byte header)
        let mut offset = 20;
        while offset + 4 <= response.len() {
            let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let attr_len = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;

            if attr_type == 0x0020 {
                // XOR-MAPPED-ADDRESS
                if offset + 4 + 8 <= response.len() && attr_len >= 8 {
                    let family = response[offset + 5];
                    let xport = u16::from_be_bytes([response[offset + 6], response[offset + 7]]);
                    // XOR with magic cookie first 2 bytes (0x2112)
                    let port = xport ^ 0x2112;

                    if family == 0x01 {
                        // IPv4
                        let xip = u32::from_be_bytes([
                            response[offset + 8],
                            response[offset + 9],
                            response[offset + 10],
                            response[offset + 11],
                        ]);
                        let ip = xip ^ 0x2112A442u32;
                        let ip_bytes = ip.to_be_bytes();
                        let ip_str = format!(
                            "{}.{}.{}.{}",
                            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                        );
                        return Ok(StunResult {
                            public_ip: ip_str,
                            public_port: port,
                        });
                    }
                }
            }

            // Skip attribute (4-byte header + data, padded to 4-byte boundary)
            let padded_len = (attr_len + 3) & !3;
            offset += 4 + padded_len;
        }

        Err(P2pError::Nat("No XOR-MAPPED-ADDRESS in STUN response".to_string()))
    }

    /// Detect NAT type by querying multiple STUN servers.
    pub async fn detect_nat_type(&mut self) -> NatType {
        let mut results = Vec::new();

        for server in &self.stun_servers {
            if let Ok(result) = self.query_stun(server).await {
                results.push(result);
            }
        }

        if results.is_empty() {
            self.nat_type = NatType::Unknown;
        } else if results.len() == 1 {
            self.nat_type = NatType::Open;
        } else {
            // Check if we get the same mapping from different servers
            let first = &results[0];
            let same_mapping = results.iter().all(|r| r.public_ip == first.public_ip && r.public_port == first.public_port);

            self.nat_type = if same_mapping {
                NatType::FullCone
            } else {
                NatType::Symmetric
            };
        }

        self.nat_type.clone()
    }

    /// Get the current NAT type.
    pub fn nat_type(&self) -> &NatType {
        &self.nat_type
    }

    /// Initiate UDP hole punching to a peer.
    /// Sends UDP packets to the peer's public and likely private addresses.
    pub async fn hole_punch(
        &self,
        peer_public: SocketAddr,
        peer_local: Option<SocketAddr>,
    ) -> Result<(), P2pError> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| P2pError::Nat(format!("UDP bind: {}", e)))?;

        // Send hole-punch packets
        let payload = b"add-p2p-hole-punch";

        for _ in 0..5 {
            socket
                .send_to(payload, peer_public)
                .await
                .map_err(|e| P2pError::Nat(format!("hole punch send: {}", e)))?;

            if let Some(local) = peer_local {
                socket
                    .send_to(payload, local)
                    .await
                    .map_err(|e| P2pError::Nat(format!("hole punch local: {}", e)))?;
            }

            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        info!("UDP hole punching complete to {}", peer_public);
        Ok(())
    }
}

impl Default for NatManager {
    fn default() -> Self {
        Self::new()
    }
}
