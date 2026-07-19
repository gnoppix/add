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

/// Configuration for creating a DHT node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub null_id: String,
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    pub ssl_certfile: String,
    pub ssl_keyfile: String,
    pub stealth_mode: bool,
    pub db_path: Option<String>,
    /// Public URL advertised in DHT records when behind a reverse proxy.
    /// If set, this URL is used as the node's address in DHT instead of host:port.
    /// Example: "wss://bootstrap.gnoppix.org" when nginx terminates TLS on :443
    /// and forwards to the node on localhost:9001.
    pub advertised_url: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            null_id: String::new(),
            host: "0.0.0.0".to_string(),
            port: 0,
            fingerprint: String::new(),
            ssl_certfile: String::new(),
            ssl_keyfile: String::new(),
            stealth_mode: false,
            db_path: None,
            advertised_url: None,
        }
    }
}

/// A node in the Kademlia routing table.
#[derive(Debug, Clone)]
pub struct RoutingEntry {
    pub node_id: u128,
    pub address: String,
    pub null_id: String,
    pub last_seen: f64,
}

/// The DHT node struct (data only, no runtime).
/// Use `DhtNodeRuntime` for the full async server.
#[derive(Debug, Clone)]
pub struct DhtNode {
    pub null_id: String,
    pub fingerprint: String,
    pub node_id: u128,
    pub host: String,
    pub port: u16,
    pub address: String,
    pub routing_table: HashMap<u128, Vec<RoutingEntry>>,
}

impl DhtNode {
    /// Derive a 160-bit Kademlia node ID from a Null ID.
    pub fn node_id_from_nid(nid: &str) -> u128 {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(nid.as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        u128::from_be_bytes(bytes)
    }

    /// Hash a DHT key to a 160-bit integer for XOR distance.
    pub fn hash_key(key: &str) -> u128 {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(key.as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        u128::from_be_bytes(bytes)
    }

    /// XOR distance between two node IDs.
    pub fn xor_distance(a: u128, b: u128) -> u128 {
        a ^ b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_from_nid() {
        let id1 = DhtNode::node_id_from_nid("NN-ABCD-EFGH");
        let id2 = DhtNode::node_id_from_nid("NN-ABCD-EFGH");
        assert_eq!(id1, id2);

        let id3 = DhtNode::node_id_from_nid("NN-IJKL-MNOP");
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_xor_distance() {
        let a: u128 = 0b1010;
        let b: u128 = 0b1100;
        assert_eq!(DhtNode::xor_distance(a, b), 0b0110);
    }
}
