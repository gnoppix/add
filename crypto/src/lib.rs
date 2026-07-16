//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
//-------------------------------------------------------------------------------
// Add Crypto — Kyber KEM + Double Ratchet for all user messages.
//-------------------------------------------------------------------------------

use std::collections::HashMap;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine;
use generic_array::typenum::U12;
use hkdf::Hkdf;
use ml_kem::MlKem1024;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;
pub mod kyber;
pub use kyber::MlKem1024EncapsulationKey;
pub use kyber::MlKem1024Keypair;
pub use kyber::MlKemVariant;
pub use kyber::VariantKeypair;
pub mod cbnp;
pub mod delivery_tokens;
pub mod hardware_keys;
pub mod pir;
pub mod secure_mem;
pub mod snapshot_defense;
pub mod tpm_vault;
pub use tpm_vault::{MasterAppKey, VaultFile, VaultKind};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid fingerprint: {0}")]
    InvalidFingerprint(String),
    #[error("encryption failed: {0}")]
    EncryptFailed(String),
    #[error("decryption failed: {0}")]
    DecryptFailed(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("ratchet error: {0}")]
    Ratchet(String),
    #[error("key persistence error: {0}")]
    KeyPersistence(String),
    #[error("PIR error: {0}")]
    Pir(String),
    #[error("hardware/TPM error: {0}")]
    HardwareError(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("key derivation failed: {0}")]
    DerivationFailed(String),
}

impl From<std::io::Error> for CryptoError {
    fn from(e: std::io::Error) -> Self {
        CryptoError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for CryptoError {
    fn from(e: serde_json::Error) -> Self {
        CryptoError::Serialization(e.to_string())
    }
}

const NONCE_SIZE: usize = 12;

// SECURITY FIX (AUDIT-4): bound the skipped-key table and the skip-forward
// window. Previously `skipped_keys` grew without limit on every decrypt and
// the simple_decrypt skip loop would advance the chain by an attacker-chosen
// `seq` count, enabling memory + CPU exhaustion.
const MAX_SKIPPED_KEYS: usize = 1024;
/// Reject gaps larger than this between the current position and `seq`, so a
/// crafted huge `seq` cannot force an unbounded number of derive steps.
const MAX_SKIP_AHEAD: u64 = 1024;

pub fn validate_fingerprint(fp: &str) -> Result<(), CryptoError> {
    let cleaned = fp.replace(' ', "").to_uppercase();
    if !(32..=40).contains(&cleaned.len()) {
        return Err(CryptoError::InvalidFingerprint(
            "fingerprint must be 32-40 hex chars".to_string(),
        ));
    }
    if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CryptoError::InvalidFingerprint(
            "fingerprint contains non-hex characters".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_null_id(nid: &str) -> Result<(), CryptoError> {
    let parts: Vec<&str> = nid.split('-').collect();
    if parts.len() != 3 || parts[0] != "NN" || parts[1].len() != 4 || parts[2].len() != 4 {
        return Err(CryptoError::InvalidFingerprint(
            "null ID must be NN-XXXX-XXXX format".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_null_id_strict(nid: &str, fingerprint: &str) -> Result<(), CryptoError> {
    validate_null_id(nid)?;
    validate_fingerprint(fingerprint)?;
    let expected = null_id(fingerprint);
    if nid != expected {
        return Err(CryptoError::InvalidFingerprint(format!(
            "null ID {} does not match fingerprint-derived ID {}",
            nid, expected
        )));
    }
    Ok(())
}

pub fn null_id(fingerprint: &str) -> String {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = Blake2bVar::new(8).expect("valid");
    Update::update(&mut hasher, fingerprint.as_bytes());
    let mut result = [0u8; 8];
    let _ = hasher.finalize_variable(&mut result);
    let b64 = base64::engine::general_purpose::STANDARD.encode(result);
    let b64 = b64.trim_end_matches('=');
    let b64: String = b64.chars().take(8).collect();
    format!("NN-{}-{}", &b64[..4], &b64[4..8])
}

// ------------------------------------------------------------------ //
//  Double Ratchet Session                                            //
// ------------------------------------------------------------------ //

// SECURITY FIX (H1): `RatchetState` holds root/chain keys — no `Debug` derive
// (would print key material on panic/log). `DoubleRatchetSession` provides a
// redacted manual `Debug` below.
#[derive(Serialize, Deserialize, Clone)]
pub struct RatchetState {
    pub peer_fp: String,
    pub peer_nid: String,
    pub our_fp: String,
    pub is_initiator: bool,
    pub self_mode: bool,
    pub root_key: Vec<u8>,
    pub send_chain_key: Vec<u8>,
    pub recv_chain_key: Vec<u8>,
    pub send_message_number: u64,
    pub recv_message_number: u64,
    pub skipped_keys: HashMap<String, Vec<u8>>,
}

pub struct DoubleRatchetSession {
    state: RatchetState,
}

impl std::fmt::Debug for DoubleRatchetSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoubleRatchetSession")
            .field("peer_fp", &self.state.peer_fp)
            .field("peer_nid", &self.state.peer_nid)
            .field("root_key", &"<secret redacted>")
            .field("send_chain_key", &"<secret redacted>")
            .field("recv_chain_key", &"<secret redacted>")
            .field("skipped_keys", &self.state.skipped_keys.len())
            .finish()
    }
}

impl DoubleRatchetSession {
    pub fn new(
        peer_fp: &str,
        peer_nid: &str,
        our_fp: &str,
        is_initiator: bool,
        shared_secret: &[u8],
    ) -> Result<Self, CryptoError> {
        Self::new_with_mode(
            peer_fp,
            peer_nid,
            our_fp,
            is_initiator,
            false,
            shared_secret,
        )
    }

    /// Self-message session: a single shared ratchet chain (both send and recv
    /// derive from the same key) so the same entity can encrypt and decrypt its
    /// own messages. The enclosed shared secret is random per send, so each
    /// self first-message re-derives a fresh shared chain — which is fine
    /// because both directions use it identically.
    pub fn new_self(
        peer_fp: &str,
        peer_nid: &str,
        our_fp: &str,
        shared_secret: &[u8],
    ) -> Result<Self, CryptoError> {
        Self::new_with_mode(peer_fp, peer_nid, our_fp, true, true, shared_secret)
    }

    fn new_with_mode(
        peer_fp: &str,
        peer_nid: &str,
        our_fp: &str,
        is_initiator: bool,
        self_mode: bool,
        shared_secret: &[u8],
    ) -> Result<Self, CryptoError> {
        if shared_secret.len() < 32 {
            return Err(CryptoError::Ratchet(
                "shared_secret must be at least 32 bytes".into(),
            ));
        }
        let hk = Hkdf::<Sha256>::new(None, shared_secret);
        let mut root_key = vec![0u8; 32];
        let mut chain_keys = vec![0u8; 64];
        hk.expand(b"add-double-ratchet-v1-root", &mut root_key)
            .map_err(|_| CryptoError::Ratchet("HKDF root_key".into()))?;
        hk.expand(b"add-double-ratchet-v1-chains", &mut chain_keys)
            .map_err(|_| CryptoError::Ratchet("HKDF chain_keys".into()))?;
        let (send_ck, mut recv_ck) = if is_initiator {
            (chain_keys[..32].to_vec(), chain_keys[32..].to_vec())
        } else {
            (chain_keys[32..].to_vec(), chain_keys[..32].to_vec())
        };
        if self_mode {
            // Single shared chain: sender and receiver share one keystream.
            recv_ck = send_ck.clone();
        }
        Ok(Self {
            state: RatchetState {
                peer_fp: peer_fp.to_string(),
                peer_nid: peer_nid.to_string(),
                our_fp: our_fp.to_string(),
                is_initiator,
                root_key,
                send_chain_key: send_ck.clone(),
                recv_chain_key: recv_ck.clone(),
                send_message_number: 0,
                recv_message_number: 0,
                self_mode,
                skipped_keys: HashMap::new(),
            },
        })
    }

    fn derive_message_key(chain_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let hk = Hkdf::<Sha256>::new(None, chain_key);
        let mut output = vec![0u8; 64];
        hk.expand(b"add-double-ratchet-v1-step", &mut output)
            .map_err(|_| CryptoError::Ratchet("HKDF step".into()))?;
        let msg_key = output[..32].to_vec();
        let new_ck = output[32..].to_vec();
        output.zeroize();
        Ok((msg_key, new_ck))
    }

    /// SECURITY FIX (AUDIT-4): keep `skipped_keys` bounded. Evict one entry
    /// when over the cap so the table cannot grow without limit under a flood
    /// of out-of-order/duplicate messages.
    fn prune_skipped_keys(&mut self) {
        if self.state.skipped_keys.len() > MAX_SKIPPED_KEYS {
            if let Some(k) = self.state.skipped_keys.keys().next().cloned() {
                self.state.skipped_keys.remove(&k);
            }
        }
    }

    pub fn encrypt_first(
        &mut self,
        plaintext: &str,
        _kyber_ct: &[u8],
        _shared_secret: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let (msg_key, new_ck) = Self::derive_message_key(&self.state.send_chain_key)?;
        // Standard double-ratchet: sending advances ONLY the send chain.
        // In self_mode the send and recv chains are the same, so advance both.
        self.state.send_chain_key.zeroize();
        self.state.send_chain_key = new_ck.clone();
        if self.state.self_mode {
            self.state.recv_chain_key.zeroize();
            self.state.recv_chain_key = new_ck;
        }
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&msg_key));
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| CryptoError::EncryptFailed(format!("AES-GCM: {}", e)))?;
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        self.state.send_message_number += 1;
        Ok(result)
    }

    pub fn encrypt_message(
        &mut self,
        plaintext: &str,
        recipient_kyber_enc: &MlKem1024EncapsulationKey,
    ) -> Result<Vec<u8>, CryptoError> {
        // Fresh Kyber encapsulation per message
        let (kyber_ct, kyber_ss) = MlKem1024Keypair::encapsulate(recipient_kyber_enc)
            .map_err(|e| CryptoError::EncryptFailed(format!("kyber encapsulate: {}", e)))?;
        // Mix Kyber SS into send chain key
        let mut mixed = Vec::new();
        mixed.extend_from_slice(&self.state.send_chain_key);
        mixed.extend_from_slice(kyber_ss.as_ref());
        let (msg_key, new_ck) = Self::derive_message_key(&mixed)?;
        let _ss_bytes: &[u8] = kyber_ss.as_ref();
        mixed.zeroize();
        self.state.send_chain_key.zeroize();
        self.state.send_chain_key = new_ck.clone();
        // Sending advances ONLY the send chain (standard double-ratchet).
        // In self_mode send and recv are one chain, so advance both.
        if self.state.self_mode {
            self.state.recv_chain_key.zeroize();
            self.state.recv_chain_key = new_ck;
        }
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&msg_key));
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| CryptoError::EncryptFailed(format!("AES-GCM: {}", e)))?;
        let kyber_ct_bytes: &[u8] = kyber_ct.as_ref();
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(kyber_ct_bytes);
        result.extend_from_slice(&(kyber_ct_bytes.len() as u16).to_be_bytes());
        let _total_len = result.len();
        self.state.send_message_number += 1;
        Ok(result)
    }

    pub fn decrypt_message(
        &mut self,
        ciphertext_b64: &str,
        our_kyber: &MlKem1024Keypair,
        seq: u64,
    ) -> Result<String, CryptoError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(ciphertext_b64)
            .map_err(|e| CryptoError::DecryptFailed(format!("base64 decode: {}", e)))?;
        if raw.len() < NONCE_SIZE + 16 + 2 {
            return Err(CryptoError::DecryptFailed("ciphertext too short".into()));
        }
        let nonce = Nonce::from_slice(&raw[..NONCE_SIZE]);
        let body = &raw[NONCE_SIZE..];

        // SECURITY FIX (M1): skipped-key lookup first. This handles
        // out-of-order delivery and replays without re-advancing the chain
        // (which would desync it). The key for `seq` was stored when first
        // derived below.
        let seq_key = seq.to_string();
        if let Some(stored) = self.state.skipped_keys.get(&seq_key).cloned() {
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&stored));
            let pt = cipher
                .decrypt(nonce, body)
                .map_err(|e| CryptoError::DecryptFailed(format!("AES-GCM (skipped): {}", e)))?;
            self.state.recv_message_number = self.state.recv_message_number.max(seq + 1);
            return String::from_utf8(pt)
                .map_err(|e| CryptoError::DecryptFailed(format!("utf8: {}", e)));
        }

        // Check for Kyber CT appended (post-first-message format)
        let pt = if body.len() > 2 {
            let kyber_len =
                u16::from_be_bytes([body[body.len() - 2], body[body.len() - 1]]) as usize;
            if kyber_len > 0 && kyber_len + 2 <= body.len() {
                // Kyber path: each message independently derives its key from
                // its own Kyber CT mixed into the recv chain. The Kyber CT is
                // self-binding, so out-of-order messages simply fail to decrypt
                // (the recv chain would be at the wrong position) — fail-closed,
                // no explicit in-order enforcement needed. `seq` is stored below
                // for replay handling via skipped_keys.
                let aes_ct_end = body.len() - 2 - kyber_len;
                let aes_ct = &body[..aes_ct_end];
                let kyber_ct_bytes = &body[aes_ct_end..body.len() - 2];
                let kyber_ct = ml_kem::kem::Ciphertext::<MlKem1024>::try_from(kyber_ct_bytes)
                    .map_err(|e| CryptoError::DecryptFailed(format!("kyber parse: {:?}", e)))?;
                let kyber_ss = our_kyber
                    .decapsulate(&kyber_ct)
                    .map_err(|e| CryptoError::DecryptFailed(format!("kyber dec: {}", e)))?;
                // Mix into recv chain
                let mut mixed = Vec::new();
                mixed.extend_from_slice(&self.state.recv_chain_key);
                mixed.extend_from_slice(kyber_ss.as_ref());
                let (msg_key, new_ck) = Self::derive_message_key(&mixed)?;
                mixed.zeroize();
                if !self.state.self_mode {
                    self.state.recv_chain_key.zeroize();
                    self.state.recv_chain_key = new_ck;
                }
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&msg_key));
                let pt = cipher
                    .decrypt(nonce, aes_ct)
                    .map_err(|e| CryptoError::DecryptFailed(format!("AES-GCM: {}", e)))?;
                self.state.recv_message_number += 1;
                // Store for replay/out-of-order (M1)
                self.state.skipped_keys.insert(seq_key, msg_key);
                self.prune_skipped_keys();
                pt
            } else {
                // Fallback: simple (linear, no-Kyber) format. This handles both
                // genuine first messages (produced by `encrypt_first`, no Kyber
                // CT, decrypted here per the caller's contract) and any body
                // whose trailing 2-byte length is zero/garbage. A tampered
                // post-first message with a stripped Kyber CT cannot be silently
                // downgraded: the linear path derives its key from the recv chain
                // key and AES-GCM authentication fails, so it is rejected rather
                // than decrypted under a weaker key.
                self.simple_decrypt(nonce, body, seq)?
            }
        } else {
            // Simple format (first message): nonce + AES ciphertext
            self.simple_decrypt(nonce, body, seq)?
        };
        String::from_utf8(pt).map_err(|e| CryptoError::DecryptFailed(format!("utf8: {}", e)))
    }

    pub fn decrypt_first(
        &mut self,
        ciphertext_b64: &str,
        _our_kyber: &MlKem1024Keypair,
    ) -> Result<String, CryptoError> {
        // First message: blob is nonce || AES-CT (NO Kyber appended).
        // recv_chain_key already derives from the root key (set in new()),
        // which matches the initiator's send_chain_key. Use simple_decrypt
        // with seq 0.
        let raw = base64::engine::general_purpose::STANDARD
            .decode(ciphertext_b64)
            .map_err(|e| CryptoError::DecryptFailed(format!("base64 decode: {}", e)))?;
        if raw.len() < NONCE_SIZE + 16 {
            return Err(CryptoError::DecryptFailed("ciphertext too short".into()));
        }
        let nonce = Nonce::from_slice(&raw[..NONCE_SIZE]);
        let body = &raw[NONCE_SIZE..];
        let pt = self.simple_decrypt(nonce, body, 0)?;
        String::from_utf8(pt).map_err(|e| CryptoError::DecryptFailed(format!("utf8: {}", e)))
    }

    /// SECURITY FIX (M1): decrypt on the linear (no-Kyber) chain, supporting
    /// out-of-order delivery via skipped-key storage. If `seq` is ahead of the
    /// current position, the chain is advanced one step per skipped index,
    /// storing each derived message key so a later-arriving message at that
    /// index can be decrypted without re-advancing (which would desync).
    fn simple_decrypt(
        &mut self,
        nonce: &Nonce<U12>,
        body: &[u8],
        seq: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        // Skip forward, storing intermediate message keys (M1).
        // SECURITY FIX (AUDIT-4): bound the gap so a crafted huge `seq` cannot
        // force an unbounded number of HKDF derive steps (CPU exhaustion).
        if seq.saturating_sub(self.state.recv_message_number) > MAX_SKIP_AHEAD {
            return Err(CryptoError::DecryptFailed("seq gap too large".into()));
        }
        while self.state.recv_message_number < seq {
            let (mk, new_ck) = Self::derive_message_key(&self.state.recv_chain_key)?;
            if !self.state.self_mode {
                self.state.recv_chain_key.zeroize();
                self.state.recv_chain_key = new_ck;
            }
            let idx = self.state.recv_message_number;
            self.state.skipped_keys.insert(idx.to_string(), mk);
            self.prune_skipped_keys();
            self.state.recv_message_number += 1;
        }
        let (msg_key, new_ck) = Self::derive_message_key(&self.state.recv_chain_key)?;
        if !self.state.self_mode {
            // Two-party mode: advance the chain for forward secrecy.
            self.state.recv_chain_key.zeroize();
            self.state.recv_chain_key = new_ck;
        }
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&msg_key));
        let pt = cipher
            .decrypt(nonce, body)
            .map_err(|e| CryptoError::DecryptFailed(format!("AES-GCM: {}", e)))?;
        self.state.recv_message_number += 1;
        // Store this message's key for replay/out-of-order (M1)
        self.state.skipped_keys.insert(seq.to_string(), msg_key);
        self.prune_skipped_keys();
        Ok(pt)
    }

    pub fn serialize(&self) -> Result<zeroize::Zeroizing<String>, CryptoError> {
        // SECURITY FIX (H2): return a `Zeroizing<String>` so the plaintext JSON
        // (which embeds root/chain keys) is zeroized as soon as the caller drops
        // it after persisting — it never lingers in memory.
        let json = serde_json::to_string(&self.state)?;
        Ok(zeroize::Zeroizing::new(json))
    }

    pub fn deserialize(data: &str) -> Result<Self, CryptoError> {
        let state: RatchetState = serde_json::from_str(data)?;
        Ok(Self { state })
    }
}

// ------------------------------------------------------------------ //
//  Tests                                                              //
// ------------------------------------------------------------------ //

#[cfg(test)]
mod tests {
    use super::kyber::MlKem1024Keypair;
    use super::*;

    #[test]
    fn test_null_id_known() {
        // Test that null_id produces base64-encoded NN IDs
        let fp = "96BC6B202299B0F1B52784FE87238E411A5F5FFA";
        let nid = null_id(fp);
        assert!(nid.starts_with("NN-"));
        assert_eq!(nid.len(), 12); // NN-XXXX-XXXX
    }

    #[test]
    fn test_validate_fingerprint_valid() {
        assert!(validate_fingerprint("96BC6B202299B0F1B52784FE87238E411A5F5FFA").is_ok());
        assert!(validate_fingerprint("96BC6B202299B0F1B52784FE87238E41").is_ok());
    }

    #[test]
    fn test_validate_null_id_valid() {
        assert!(validate_null_id("NN-ABCD-EFGH").is_ok());
        assert!(validate_null_id("NN-X1Y2-Z3W4").is_ok());
    }

    #[test]
    fn test_validate_null_id_invalid() {
        assert!(validate_null_id("").is_err());
        assert!(validate_null_id("XX-ABCD-EFGH").is_err());
    }

    /// Bidirectional double-ratchet round-trip (regression test for wire format fix).
    /// Verifies that initiator↔responder encrypt/decrypt works across multiple hops.
    #[test]
    fn test_bidirectional_ratchet_roundtrip() {
        use base64::Engine;
        let kp_bytes = [0x42u8; 64];
        let kp = MlKem1024Keypair::from_seed(&kp_bytes).unwrap();
        let enc_key = kp.enc.clone();
        let ct_base64 = base64::engine::general_purpose::STANDARD;

        // Two sessions sharing same ratchet keys (simulating key exchange).
        // Initiator's send_ck must equal responder's recv_ck and vice versa.
        let shared_send_ck = [0xABu8; 32];
        let shared_recv_ck = [0xCDu8; 32];
        let shared_secret = [0xEFu8; 32];

        let mut sess_a =
            DoubleRatchetSession::new("fp-a", "NN-AAAA-BBBB", "our-fp-a", true, &shared_secret)
                .unwrap();
        let mut sess_b =
            DoubleRatchetSession::new("fp-b", "NN-CCCC-DDDD", "our-fp-b", false, &shared_secret)
                .unwrap();

        // Overwrite chain keys to simulate matching ratchet state
        sess_a.state.send_chain_key = shared_send_ck.to_vec();
        sess_a.state.recv_chain_key = shared_recv_ck.to_vec();
        sess_b.state.send_chain_key = shared_recv_ck.to_vec();
        sess_b.state.recv_chain_key = shared_send_ck.to_vec();

        // A sends first message to B (simple_decrypt path, no kyber CT in payload)
        let pt1 = "hello from A";
        let ct1_raw = sess_a.encrypt_first(pt1, &[], &[]).unwrap();
        let ct1_b64 = ct_base64.encode(&ct1_raw);
        let dec1 = sess_b.decrypt_message(&ct1_b64, &kp, 0).unwrap();
        assert_eq!(dec1, pt1, "first message decrypt failed");

        // B sends reply to A (kyber CT appended — the path we fixed)
        let pt2 = "reply from B";
        let ct2_raw = sess_b.encrypt_message(pt2, &enc_key).unwrap();
        let ct2_b64 = ct_base64.encode(&ct2_raw);
        let dec2 = sess_a.decrypt_message(&ct2_b64, &kp, 1).unwrap();
        assert_eq!(dec2, pt2, "reply decrypt failed — WIRE FORMAT BUG");

        // A sends second message (continues the ratchet)
        let pt3 = "second from A";
        let ct3_raw = sess_a.encrypt_message(pt3, &enc_key).unwrap();
        let ct3_b64 = ct_base64.encode(&ct3_raw);
        let dec3 = sess_b.decrypt_message(&ct3_b64, &kp, 2).unwrap();
        assert_eq!(dec3, pt3, "third message decrypt failed");

        // B replies again — multi-hop bidirectional ratchet
        let pt4 = "second reply from B";
        let ct4_raw = sess_b.encrypt_message(pt4, &enc_key).unwrap();
        let ct4_b64 = ct_base64.encode(&ct4_raw);
        let dec4 = sess_a.decrypt_message(&ct4_b64, &kp, 3).unwrap();
        assert_eq!(dec4, pt4, "fourth message decrypt failed");
    }

    #[test]
    fn test_ratchet_skipped_keys_out_of_order_and_replay() {
        // SECURITY FIX (M1): the ratchet must recover out-of-order delivery and
        // tolerate replays via the skipped_keys map, without desyncing.
        use base64::Engine;
        let kp_bytes = [0x42u8; 64];
        let kp = MlKem1024Keypair::from_seed(&kp_bytes).unwrap();
        let ct_base64 = base64::engine::general_purpose::STANDARD;

        let shared_secret = [0x11u8; 32];
        let mut sess_a =
            DoubleRatchetSession::new("fp-a", "NN-AAAA-BBBB", "our-fp-a", true, &shared_secret)
                .unwrap();
        let mut sess_b =
            DoubleRatchetSession::new("fp-b", "NN-CCCC-DDDD", "our-fp-b", false, &shared_secret)
                .unwrap();
        sess_a.state.send_chain_key = [0xABu8; 32].to_vec();
        sess_a.state.recv_chain_key = [0xCDu8; 32].to_vec();
        sess_b.state.send_chain_key = [0xCDu8; 32].to_vec();
        sess_b.state.recv_chain_key = [0xABu8; 32].to_vec();

        // B prepares a batch of messages (seq 0,1,2,3) on the SIMPLE chain
        // (no Kyber CT) so that skip-forward / skipped_keys handling applies.
        let mut cts = Vec::new();
        for i in 0..4u64 {
            let raw = sess_b.encrypt_first(&format!("m{}", i), &[], &[]).unwrap();
            cts.push(ct_base64.encode(&raw));
        }

        // A receives them OUT OF ORDER: 2, 0, 3, 1, then replays 0 and 2.
        let mut got = std::collections::HashMap::new();
        for seq in [2u64, 0, 3, 1, 0, 2] {
            let plain = sess_a
                .decrypt_message(&cts[seq as usize], &kp, seq)
                .unwrap();
            got.insert(seq, plain);
        }
        assert_eq!(got[&0], "m0");
        assert_eq!(got[&1], "m1");
        assert_eq!(got[&2], "m2");
        assert_eq!(got[&3], "m3");
        // Replays must decrypt identically (skipped_keys lookup, no chain advance).
        let replay = sess_a.decrypt_message(&cts[1], &kp, 1).unwrap();
        assert_eq!(replay, "m1");
    }
}
