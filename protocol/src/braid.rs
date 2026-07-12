//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// Add ML-KEM-1024 SPQR Braid Protocol
//
// Implements chunk-based key exchange for large post-quantum keys (ML-KEM-1024).
// The braid protocol enables streaming key exchange to avoid latency spikes.
//
// ACS2.6 Part I.1 requirement: SPQR (Secure Parallelizable Quantum-Resistant) protocol.
// -------------------------------------------------------------------------------

use serde::{Deserialize, Serialize};

/// A chunk in the braid protocol exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BraidChunk {
    /// Chunk sequence number (0-indexed)
    pub chunk_num: u32,
    /// Total number of chunks in this exchange
    pub total_chunks: u32,
    /// SHA-512 hash of the encapsulation key (64 bytes)
    pub ek_hash: Vec<u8>,
    /// The seed extracted from the encapsulation key (32 bytes)
    pub seed: Vec<u8>,
    /// Chunk payload (partial key material)
    pub payload: Vec<u8>,
}

/// State machine for ML-KEM-1024 SPQR braid handshake.
#[derive(Debug)]
pub struct BraidHandshake {
    pub total_chunks: u32,
    pub received_chunks: Vec<BraidChunk>,
    pub ek_hash: Vec<u8>,
    pub complete: bool,
}

impl BraidHandshake {
    /// Create a new braid handshake for ML-KEM-1024 key exchange.
    /// ML-KEM-1024 public key = 1568 bytes, split into chunks of CHUNK_SIZE.
    pub fn new() -> Self {
        Self {
            total_chunks: 0,
            received_chunks: Vec::new(),
            ek_hash: vec![0u8; 64],
            complete: false,
        }
    }

    /// CHUNK_SIZE: 64 bytes per chunk (allows parallel processing)
    pub const CHUNK_SIZE: usize = 64;

    /// Add a received chunk and return true if handshake is complete.
    pub fn add_chunk(&mut self, chunk: BraidChunk) -> Result<bool, String> {
        // Validate chunk_num bounds
        if chunk.chunk_num >= chunk.total_chunks {
            return Err(format!(
                "chunk_num {} >= total_chunks {}",
                chunk.chunk_num, chunk.total_chunks
            ));
        }

        // Initialize ek_hash on first chunk
        if self.total_chunks == 0 {
            self.total_chunks = chunk.total_chunks;
            self.ek_hash.clone_from(&chunk.ek_hash);
        }

        // Verify ek_hash consistency
        if self.ek_hash != chunk.ek_hash {
            return Err("ek_hash mismatch".to_string());
        }

        // Check for duplicate
        for c in &self.received_chunks {
            if c.chunk_num == chunk.chunk_num {
                return Err("duplicate chunk".to_string());
            }
        }

        self.received_chunks.push(chunk);

        // Check if complete
        if self.received_chunks.len() == self.total_chunks as usize {
            self.complete = true;
        }

        Ok(self.complete)
    }

    /// Reconstruct the full encapsulation key from chunks.
    /// `key_len` must be the original key byte length.
    pub fn reconstruct_enc_key(&self, key_len: usize) -> Vec<u8> {
        let mut key = vec![0u8; key_len];
        for chunk in &self.received_chunks {
            let start = chunk.chunk_num as usize * Self::CHUNK_SIZE;
            let end = start + chunk.payload.len().min(Self::CHUNK_SIZE);
            if end <= key.len() {
                key[start..end].copy_from_slice(&chunk.payload[..end - start]);
            }
        }
        key
    }
}

impl Default for BraidHandshake {
    fn default() -> Self {
        Self::new()
    }
}

use sha2::{Digest, Sha512};

/// Split a key into braid chunks for streaming exchange.
pub fn split_key_to_chunks(key: &[u8]) -> Vec<BraidChunk> {
    let total_chunks = key.len().div_ceil(BraidHandshake::CHUNK_SIZE);
    let ek_hash = {
        let mut hasher = Sha512::new();
        hasher.update(key);
        hasher.finalize().to_vec()
    };
    let seed = &key[..32.min(key.len())];

    key.chunks(BraidHandshake::CHUNK_SIZE)
        .enumerate()
        .map(|(i, chunk)| BraidChunk {
            chunk_num: i as u32,
            total_chunks: total_chunks as u32,
            ek_hash: ek_hash.clone(),
            seed: seed.to_vec(),
            payload: chunk.to_vec(),
        })
        .collect()
}

/// ML-KEM-1024 encapsulation-key length in bytes (fixed by the parameter set).
/// The braid receiver reconstructs exactly this many bytes.
pub const MLKEM1024_EK_LEN: usize = 1568;

/// Parse a `BraidChunk` back out of a wire envelope produced by
/// [`build_braid_chunk_msg`]. Returns `None` if any field is missing or
/// malformed, so callers can safely skip non-braid frames.
pub fn parse_braid_chunk(env: &WireEnvelope) -> Option<BraidChunk> {
    if env.msg_type != MSG_P2P_BRAID_CHUNK {
        return None;
    }
    let p = env.payload.as_object()?;
    let as_bytes = |v: &serde_json::Value| -> Option<Vec<u8>> {
        v.as_array()?
            .iter()
            .map(|n| n.as_u64().filter(|b| *b <= 255).map(|b| b as u8))
            .collect()
    };
    Some(BraidChunk {
        chunk_num: p.get("chunk_num")?.as_u64()? as u32,
        total_chunks: p.get("total_chunks")?.as_u64()? as u32,
        ek_hash: as_bytes(p.get("ek_hash")?)?,
        seed: as_bytes(p.get("seed")?)?,
        payload: as_bytes(p.get("payload")?)?,
    })
}

/// Build a braid-chunk wire envelope (for p2p transport).
pub fn build_braid_chunk_msg(chunk: &BraidChunk) -> WireEnvelope {
    WireEnvelope {
        msg_type: MSG_P2P_BRAID_CHUNK.to_string(),
        payload: serde_json::json!({
            "chunk_num": chunk.chunk_num,
            "total_chunks": chunk.total_chunks,
            "ek_hash": chunk.ek_hash,
            "seed": chunk.seed,
            "payload": chunk.payload,
        }),
        msg_id: uuid_hex(),
        ts: now_unix(),
        sig: String::new(),
    }
}

/// Wire-format helper functions.
fn uuid_hex() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes);
    hex::encode(bytes)
}

fn now_unix() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

use crate::constants::MSG_P2P_BRAID_CHUNK;
use crate::envelope::WireEnvelope;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_reconstruct_1568_key() {
        // ML-KEM-1024 public key: 1568 bytes
        let key: Vec<u8> = (0..1568u32).map(|i| (i % 256) as u8).collect();
        let chunks = split_key_to_chunks(&key);
        assert_eq!(chunks.len(), 25); // 1568 / 64 = 24.5 → 25 chunks
        assert_eq!(chunks[0].chunk_num, 0);
        assert_eq!(chunks[0].total_chunks, 25);
        assert_eq!(chunks[0].payload.len(), 64);
        assert_eq!(chunks[24].payload.len(), 32); // 1568 - 24*64 = 32

        // Reconstruct via BraidHandshake
        let mut handshake = BraidHandshake::new();
        for chunk in &chunks {
            let done = handshake.add_chunk(chunk.clone()).unwrap();
            if chunk.chunk_num < 24 {
                assert!(!done);
            }
        }
        assert!(handshake.complete);
        let reconstructed = handshake.reconstruct_enc_key(key.len());
        assert_eq!(reconstructed, key);
    }

    #[test]
    fn test_split_and_reconstruct_32_byte_key() {
        // Small key (32 bytes) → 1 chunk
        let key = vec![0xABu8; 32];
        let chunks = split_key_to_chunks(&key);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].payload.len(), 32);
        assert_eq!(chunks[0].total_chunks, 1);

        let mut handshake = BraidHandshake::new();
        let done = handshake.add_chunk(chunks[0].clone()).unwrap();
        assert!(done);
        assert_eq!(handshake.reconstruct_enc_key(key.len()), key);
    }

    #[test]
    fn test_ek_hash_consistency() {
        let key = vec![0x42u8; 128];
        let chunks = split_key_to_chunks(&key);
        let first_hash = chunks[0].ek_hash.clone();
        for chunk in &chunks {
            assert_eq!(&chunk.ek_hash, &first_hash);
            assert_eq!(chunk.ek_hash.len(), 64); // SHA-512 = 64 bytes
        }
    }

    #[test]
    fn test_duplicate_chunk_rejected() {
        let key = vec![0x11u8; 64];
        let chunks = split_key_to_chunks(&key);
        let mut handshake = BraidHandshake::new();
        handshake.add_chunk(chunks[0].clone()).unwrap();
        let result = handshake.add_chunk(chunks[0].clone());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate"));
    }

    #[test]
    fn test_ek_hash_mismatch_rejected() {
        // Two different keys split into chunks, but we send a chunk from key1
        // then a chunk from key2 (different ek_hash). Since both have chunk_num=0,
        // the second is caught as duplicate OR ek_hash mismatch depending on order.
        let key1 = vec![0x22u8; 128]; // 2 chunks
        let key2 = vec![0x33u8; 128]; // 2 chunks
        let chunks1 = split_key_to_chunks(&key1);
        let chunks2 = split_key_to_chunks(&key2);
        // Send chunk 0 from key1, then chunk 1 from key2 (different ek_hash)
        let mut handshake = BraidHandshake::new();
        handshake.add_chunk(chunks1[0].clone()).unwrap();
        let result = handshake.add_chunk(chunks2[1].clone());
        assert!(result.is_err());
        // chunk2 has different ek_hash than what was established by chunk1
        assert!(result.unwrap_err().contains("ek_hash"));
    }
}
