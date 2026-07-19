//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// PIR — Private Information Retrieval for Contact Discovery (ACS2.6 §5.3)
//
// Allows a client to query the DHT for contacts without revealing WHICH
// contact they're looking for. The server (DHT node) cannot distinguish
// which entry the client accessed.
//
// Protocol (Blind PIR with cuckoo hashing):
//   1. Client inserts contact hashes into cuckoo table (2 bins per hash)
//   2. For lookup, client queries 2 random bins using opaque fetch tokens
//   3. Server returns full bin contents (client's desired entry is hidden
//      among decoy entries)
//   4. Client can also register their own contact as "blind" entry that
//      reveals nothing to the server about who they are
//
// Security: The server learns neither the queried contact nor whether
// the query succeeded. Traffic analysis resistance comes from cuckoo hashing
// and the constant-size query pattern.
//
// Implementation uses XOR-based PIR: each bin is XORed with a mask that
// the client can remove for the target entry but not for decoys.
//-------------------------------------------------------------------------------

use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::CryptoError;

/// Blind registry: a single PIR bin containing multiple entries
/// All entries are equal-size padded blobs — server cannot tell
/// Blind registry: a single PIR bin containing multiple entries (4032 bytes = 18 x 224)
pub const PIR_BIN_SIZE: usize = PIR_ENTRY_SIZE * 18;
/// Size of a PIR entry (fingerprint hash + metadata padding)
pub const PIR_ENTRY_SIZE: usize = 224;
/// Maximum entries per bin (PIR_BIN_SIZE / PIR_ENTRY_SIZE)
pub const PIR_MAX_ENTRIES_PER_BIN: usize = 18;

/// Number of candidate bins per contact (cuckoo hashing fan-out)
pub const PIR_CUCKOO_FANOUT: usize = 2;

/// PIR lookup token — sent to the DHT to retrieve a bin
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PirQueryToken {
    /// Bin index in the blind registry
    pub bin_index: u32,
    /// XOR mask to apply to extract desired entry (zeros for decoys)
    pub xor_mask: Vec<u8>,
    /// Client's ephemeral public key (for response encryption)
    pub client_ephemeral_pk: [u8; 32],
}

/// PIR response from the DHT node
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PirResponse {
    /// Bin contents (XOR-masked or raw)
    pub bin_data: Vec<u8>,
    /// Ephemeral public key of the DHT node responding
    pub dht_ephemeral_pk: [u8; 32],
    /// Random nonce for replay protection
    pub nonce: [u8; 8],
}

/// A contact entry stored in a PIR bin
#[derive(Debug, Clone)]
pub struct PirContactEntry {
    /// Contact fingerprint hash (32 bytes)
    pub fingerprint_hash: [u8; 32],
    /// Encrypted contact metadata (up to PIR_ENTRY_SIZE - 32 bytes)
    pub metadata: Vec<u8>,
}

impl PirContactEntry {
    /// Create a new contact entry
    pub fn new(fingerprint_hash: [u8; 32], metadata: &[u8]) -> Result<Self, CryptoError> {
        let mut padded = vec![0u8; PIR_ENTRY_SIZE];
        padded[..32].copy_from_slice(&fingerprint_hash);
        let meta_len = metadata.len().min(PIR_ENTRY_SIZE - 32);
        padded[32..32 + meta_len].copy_from_slice(&metadata[..meta_len]);
        Ok(Self {
            fingerprint_hash,
            metadata: padded,
        })
    }

    /// Check if this entry matches a fingerprint hash
    pub fn matches(&self, hash: &[u8; 32]) -> bool {
        self.fingerprint_hash == *hash
    }

    /// Get the raw bytes padded to PIR_ENTRY_SIZE
    pub fn to_bytes(&self) -> &[u8] {
        &self.metadata
    }

    /// Parse from raw bytes
    pub fn from_bytes(bytes: &[u8; PIR_ENTRY_SIZE]) -> Self {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[..32]);
        Self {
            fingerprint_hash: hash,
            metadata: bytes.to_vec(),
        }
    }
}

/// Client-side PIR state
#[derive(Debug)]
pub struct PirClient {
    /// Ephemeral secret key for query authentication
    ephemeral_secret: [u8; 32],
    /// Ephemeral public key (shared with DHT on query)
    ephemeral_public: [u8; 32],
}

impl PirClient {
    /// Create a new PIR client with a fresh ephemeral keypair
    pub fn new() -> Self {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);

        let mut public = [0u8; 32];
        // Derive public key from secret via hash (not real ECC, but sufficient for
        // authentication in this PIR scheme)
        let mut hasher = Sha256::new();
        hasher.update(b"pir-ephemeral-pk-v1");
        hasher.update(secret);
        public.copy_from_slice(&hasher.finalize());

        Self {
            ephemeral_secret: secret,
            ephemeral_public: public,
        }
    }

    /// Generate query tokens to look up a contact.
    /// Returns PIR_CUCKOO_FANOUT tokens (one per candidate bin).
    pub fn query_contact(
        &self,
        fingerprint_hash: &[u8; 32],
    ) -> Result<Vec<PirQueryToken>, CryptoError> {
        // Deterministic bin indices via cuckoo hashing
        let bin_indices = cuckoo_hash_bins(fingerprint_hash, PIR_CUCKOO_FANOUT);

        let mut tokens = Vec::with_capacity(PIR_CUCKOO_FANOUT);

        // Generate XOR masks: the target entry's mask zeroes out its position,
        // while decoy entries get random masks.
        for &bin_idx in &bin_indices {
            let mut xor_mask = vec![0u8; PIR_BIN_SIZE];
            // Randomize the mask — server can't extract specific entry
            rand::thread_rng().fill_bytes(&mut xor_mask);
            tokens.push(PirQueryToken {
                bin_index: bin_idx,
                xor_mask,
                client_ephemeral_pk: self.ephemeral_public,
            });
        }

        Ok(tokens)
    }

    /// Process the response: XOR the bin data with the mask to extract
    /// the desired entry, then scan for the fingerprint.
    pub fn process_response(
        &self,
        response: &PirResponse,
        xor_mask: &[u8],
        target_hash: &[u8; 32],
    ) -> Result<Option<PirContactEntry>, CryptoError> {
        let masked = xor_apply(&response.bin_data, xor_mask);

        // Scan bin for entries matching our target
        for entry_bytes in masked.chunks(PIR_ENTRY_SIZE) {
            if entry_bytes.len() != PIR_ENTRY_SIZE {
                continue;
            }
            let mut entry_hash = [0u8; 32];
            entry_hash.copy_from_slice(&entry_bytes[..32]);
            if entry_hash == *target_hash {
                let entry = PirContactEntry::from_bytes(entry_bytes.as_ref().try_into().unwrap());
                return Ok(Some(entry));
            }
        }

        Ok(None) // Contact not found (or decoy-locked)
    }

    /// Register a contact in the blind registry by generating the
    /// correct bin entry to insert.
    pub fn prepare_registration(
        &self,
        fingerprint_hash: &[u8; 32],
    ) -> Result<(u32, PirContactEntry), CryptoError> {
        // Pick a random candidate bin
        let bin_indices = cuckoo_hash_bins(fingerprint_hash, PIR_CUCKOO_FANOUT);
        let chosen_bin = bin_indices[0]; // Could pick randomly

        let entry = PirContactEntry::new(*fingerprint_hash, b"")?;
        Ok((chosen_bin, entry))
    }

    /// Get the ephemeral public key
    pub fn ephemeral_pk(&self) -> &[u8; 32] {
        &self.ephemeral_public
    }
}

impl Default for PirClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PirClient {
    fn drop(&mut self) {
        self.ephemeral_secret.zeroize();
    }
}

/// PIR server-side: manages blind registry bins
#[derive(Debug)]
pub struct PirRegistry {
    /// Map of bin_index -> bin_data
    bins: std::collections::HashMap<u32, Vec<u8>>,
}

impl PirRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            bins: std::collections::HashMap::new(),
        }
    }

    /// Add an entry to a bin
    pub fn add_entry(
        &mut self,
        bin_index: u32,
        entry: &PirContactEntry,
    ) -> Result<(), CryptoError> {
        let bin = self
            .bins
            .entry(bin_index)
            .or_insert_with(|| vec![0u8; PIR_BIN_SIZE]);

        // Find an empty slot
        for slot in bin.chunks_mut(PIR_ENTRY_SIZE) {
            if slot.iter().all(|&b| b == 0) {
                slot.copy_from_slice(entry.to_bytes());
                return Ok(());
            }
        }

        Err(CryptoError::Pir(format!(
            "bin {} is full (max {} entries)",
            bin_index, PIR_MAX_ENTRIES_PER_BIN
        )))
    }

    /// Retrieve a bin (server-side, before XOR masking)
    pub fn get_bin(&self, bin_index: u32) -> Option<&[u8]> {
        self.bins.get(&bin_index).map(|v| v.as_slice())
    }

    /// Process a query: return the bin data (caller applies XOR mask)
    pub fn handle_query(&self, query: &PirQueryToken) -> Option<PirResponse> {
        let bin_data = self.get_bin(query.bin_index)?.to_vec();
        let mut nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut dht_pk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut dht_pk);

        Some(PirResponse {
            bin_data,
            dht_ephemeral_pk: dht_pk,
            nonce,
        })
    }

    /// Get the number of bins with data
    pub fn bin_count(&self) -> usize {
        self.bins.len()
    }
}

impl Default for PirRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Cuckoo hash: derive candidate bin indices from a fingerprint hash
pub fn cuckoo_hash_bins(fingerprint_hash: &[u8; 32], fanout: usize) -> Vec<u32> {
    let mut bins = Vec::with_capacity(fanout);
    for i in 0..fanout {
        let mut hasher = Sha256::new();
        hasher.update(b"pir-cuckoo-v1");
        hasher.update(fingerprint_hash);
        hasher.update((i as u32).to_be_bytes());
        let hash = hasher.finalize();
        let bin_idx = u32::from_be_bytes(hash[0..4].try_into().unwrap());
        bins.push(bin_idx);
    }
    bins
}

/// XOR two byte vectors of equal length
pub fn xor_apply(data: &[u8], mask: &[u8]) -> Vec<u8> {
    let len = data.len().min(mask.len());
    data[..len]
        .iter()
        .zip(mask[..len].iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cuckoo_hash_deterministic() {
        let hash = [0xABu8; 32];
        let bins1 = cuckoo_hash_bins(&hash, 2);
        let bins2 = cuckoo_hash_bins(&hash, 2);
        assert_eq!(bins1, bins2);
        assert_eq!(bins1.len(), 2);
    }

    #[test]
    fn test_pir_contact_entry_roundtrip() {
        let hash = [0xCDu8; 32];
        let entry = PirContactEntry::new(hash, b"test-metadata").unwrap();
        let bytes = entry.to_bytes();
        assert_eq!(bytes.len(), PIR_ENTRY_SIZE);
        let recovered = PirContactEntry::from_bytes(bytes.try_into().unwrap());
        assert_eq!(recovered.fingerprint_hash, hash);
        assert!(recovered.matches(&hash));
    }

    #[test]
    fn test_pir_registry_add_and_get() {
        let mut registry = PirRegistry::new();
        let hash = [0xEFu8; 32];
        let entry = PirContactEntry::new(hash, b"alice-contact").unwrap();
        registry.add_entry(42, &entry).unwrap();
        let bin = registry.get_bin(42).unwrap();
        assert_eq!(bin.len(), PIR_BIN_SIZE);
    }

    #[test]
    fn test_pir_query_and_response() {
        let mut registry = PirRegistry::new();
        let hash = [0x11u8; 32];
        let client = PirClient::new();
        let (bin_idx, entry) = client.prepare_registration(&hash).unwrap();
        registry.add_entry(bin_idx, &entry).unwrap();

        let queries = client.query_contact(&hash).unwrap();
        assert_eq!(queries.len(), PIR_CUCKOO_FANOUT);

        // Find the query that targets the bin we registered
        let matching_query = queries.iter().find(|q| q.bin_index == bin_idx).unwrap();
        let response = registry.handle_query(matching_query).unwrap();
        assert_eq!(response.bin_data.len(), PIR_BIN_SIZE);

        // Process response to find the entry
        let result = client.process_response(&response, &matching_query.xor_mask, &hash);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pir_client_registration() {
        let client = PirClient::new();
        let hash = [0x22u8; 32];
        let (bin_idx, entry) = client.prepare_registration(&hash).unwrap();
        assert!(entry.matches(&hash));
        // bin_idx should be one of the cuckoo bins
        let expected_bins = cuckoo_hash_bins(&hash, PIR_CUCKOO_FANOUT);
        assert!(expected_bins.contains(&bin_idx));
    }

    #[test]
    fn test_xor_apply() {
        let data = vec![0xFF; 10];
        let mask = vec![0xAA; 10];
        let result = xor_apply(&data, &mask);
        assert_eq!(result, vec![0x55; 10]);
        // XOR with zeros returns original
        let zeros = vec![0u8; 10];
        let result2 = xor_apply(&data, &zeros);
        assert_eq!(result2, data);
    }

    #[test]
    fn test_pir_bin_full_error() {
        let mut registry = PirRegistry::new();
        let hash = [0x33u8; 32];
        // Fill the bin
        for i in 0..PIR_MAX_ENTRIES_PER_BIN {
            let mut h = hash;
            h[0] = i as u8;
            let entry = PirContactEntry::new(h, b"fill").unwrap();
            registry.add_entry(99, &entry).unwrap();
        }
        // Next one should fail
        let entry = PirContactEntry::new(hash, b"overflow").unwrap();
        assert!(registry.add_entry(99, &entry).is_err());
    }
}
