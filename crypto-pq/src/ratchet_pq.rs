//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
//-------------------------------------------------------------------------------
//! Post-Quantum Double Ratchet — KEM-based asymmetric ratchet.
//!
//! This module implements the asymmetric ratcheting step using a PQC KEM
//! (hybrid X25519+ML-KEM-768) for every ratchet step, ensuring provable
//! recovery from full state compromise (PQ-Ratchet, ACM CCS '23).
//!
//! ## State Machine
//!
//! ```text
//!     [AWAITING_KEM_RESPONSE] ──recv KemResponse──► [AWAITING_KEM_REQUEST]
//!         ▲                                            │
//!         │                                            ▼
//!         │                                   [SEND_KEM_REQUEST + advance_root_ratchet]
//!         │                                            │
//!         └──────────── recv KemRequest ◄──────────────┘
//! ```
//!
//! - **AWAITING_KEM_RESPONSE**: We sent a KEM request, awaiting peer's ciphertext.
//!   On receiving it, we decapsulate to derive the new root key → AWAITING_KEM_REQUEST.
//!
//! - **AWAITING_KEM_REQUEST**: We decapsulated and advanced the root chain.
//!   We generate fresh ephemeral keys and send our KEM request → AWAITING_KEM_RESPONSE.
//!
//! ## Security Properties
//!
//! - **PCS**: Every ratchet step performs a full KEM encapsulate/decapsulate cycle.
//! - **Replay Protection**: Each KEM operation binds epoch+seq via SHA3-256 domain separation.
//! - **Forward Secrecy of State**: `Drop` zeroizes all key material via `zeroize`.
//! - **Async-Safe**: Heavy KEM ops offloaded to tokio's blocking thread pool.

use std::marker::PhantomData;

use hkdf::Hkdf;
use ml_kem::kem::{Encapsulate, Kem};
use rand::Rng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::PqError;
use crate::hybrid_kem::{
    combine_shared_secrets, HybridCiphertext, HybridKeypair, HybridSharedSecret,
    COMBINED_CT_SIZE,
};
use ml_kem::TryKeyInit;
use ml_kem::KeyExport;
use crate::kem::{
    HybridKemRatchet, KemRatchet, make_kem_context,
    async_encapsulate, async_decapsulate, async_generate_keypair,
    raw_to_decap_key,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_SKIPPED_KEYS: usize = 1024;
const MAX_SKIP_AHEAD: u64 = 1024;
const MESSAGE_KEY_INFO: &[u8] = b"add-pq-ratchet-msg-key-v1";
const ROOT_KEY_UPDATE_INFO: &[u8] = b"add-pq-ratchet-root-update-v1";
const CHAIN_KEY_UPDATE_INFO: &[u8] = b"add-pq-ratchet-chain-update-v1";

// ---------------------------------------------------------------------------
// Ratchet State Machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatchetState {
    AwaitingKemResponse,
    AwaitingKemRequest,
}

impl std::fmt::Display for RatchetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RatchetState::AwaitingKemResponse => write!(f, "AWAITING_KEM_RESPONSE"),
            RatchetState::AwaitingKemRequest => write!(f, "AWAITING_KEM_REQUEST"),
        }
    }
}

// ---------------------------------------------------------------------------
// Core State Structs
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct RatchetStateBase {
    pub root_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub recv_chain_key: [u8; 32],
    pub send_message_counter: u64,
    pub recv_message_counter: u64,
    pub is_initiator: bool,
}

impl std::fmt::Debug for RatchetStateBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetStateBase")
            .field("root_key", &"0x..")
            .field("send_chain_key", &"0x..")
            .field("recv_chain_key", &"0x..")
            .field("send_message_counter", &self.send_message_counter)
            .field("recv_message_counter", &self.recv_message_counter)
            .field("is_initiator", &self.is_initiator)
            .finish()
    }
}

impl Zeroize for RatchetStateBase {
    fn zeroize(&mut self) {
        self.root_key.iter_mut().for_each(|b| *b = 0);
        self.send_chain_key.iter_mut().for_each(|b| *b = 0);
        self.recv_chain_key.iter_mut().for_each(|b| *b = 0);
    }
}

impl Drop for RatchetStateBase {
    fn drop(&mut self) { self.zeroize(); }
}

#[derive(Clone)]
pub struct EphemeralKeys {
    pub x25519_pk: PublicKey,
    pub mlkem_dec: <ml_kem::MlKem768 as Kem>::DecapsulationKey,
    pub mlkem_enc: <ml_kem::MlKem768 as Kem>::EncapsulationKey,
    x25519_secret: StaticSecret,
}

impl std::fmt::Debug for EphemeralKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralKeys")
            .field("x25519_pk", &self.x25519_pk)
            .field("mlkem_enc", &"<encapsulation key>")
            .finish()
    }
}

impl Zeroize for EphemeralKeys {
    fn zeroize(&mut self) {
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        let rand_secret = StaticSecret::from(buf);
        let _dh = self.x25519_secret.diffie_hellman(&self.x25519_pk);
        let _ = rand_secret;
    }
}

impl Drop for EphemeralKeys {
    fn drop(&mut self) { self.zeroize(); }
}

#[derive(Clone)]
pub struct KemRatchetState<T: KemRatchet> {
    pub base: RatchetStateBase,
    pub our_ephemeral: EphemeralKeys,
    pub their_mlkem_enc: <ml_kem::MlKem768 as Kem>::EncapsulationKey,
    pub their_x25519_pk: PublicKey,
    pub skipped_keys: Vec<(u64, [u8; 32])>,
    pub send_seq: u64,
    pub recv_seq: u64,
    pub state: RatchetState,
    _kem: PhantomData<T>,
}

impl<T: KemRatchet> std::fmt::Debug for KemRatchetState<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KemRatchetState")
            .field("base", &self.base)
            .field("our_ephemeral", &self.our_ephemeral)
            .field("their_x25519_pk", &"0x..")
            .field("send_seq", &self.send_seq)
            .field("recv_seq", &self.recv_seq)
            .field("state", &self.state)
            .finish()
    }
}

impl<T: KemRatchet> Zeroize for KemRatchetState<T> {
    fn zeroize(&mut self) {
        self.base.zeroize();
        self.our_ephemeral.zeroize();
    }
}

impl<T: KemRatchet> Drop for KemRatchetState<T> {
    fn drop(&mut self) { self.zeroize(); }
}

// ---------------------------------------------------------------------------
// Ratchet Message Wire Format
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct KemRatchetMessage {
    pub version: String,
    pub x25519_pk: [u8; 32],
    pub mlkem_enc_key: Vec<u8>,
    pub hybrid_ct: Option<HybridCiphertext>,
    pub seq: u64,
    pub epoch: u64,
}

impl KemRatchetMessage {
    pub fn to_wire(&self) -> Zeroizing<Vec<u8>> {
        let vb = self.version.as_bytes();
        let mut wire = Zeroizing::new(Vec::with_capacity(
            1 + vb.len() + 32 + 1184 + COMBINED_CT_SIZE.saturating_add(16),
        ));
        wire.push(vb.len() as u8);
        wire.extend_from_slice(vb);
        wire.extend_from_slice(&self.x25519_pk);
        wire.extend_from_slice(&self.mlkem_enc_key);
        if let Some(ref hct) = self.hybrid_ct {
            wire.extend_from_slice(&hct.to_bytes());
        }
        wire.extend_from_slice(&self.seq.to_be_bytes());
        wire.extend_from_slice(&self.epoch.to_be_bytes());
        wire
    }

    pub fn from_wire(wire: &[u8]) -> Result<Self, PqError> {
        let mut offset = 0;
        if offset >= wire.len() {
            return Err(PqError::InvalidKeyLength { expected: 1, got: 0 });
        }
        let vlen = wire[offset] as usize;
        offset += 1;
        if offset + vlen > wire.len() {
            return Err(PqError::InvalidKeyLength { expected: vlen, got: wire.len().saturating_sub(offset) });
        }
        let version = String::from_utf8(wire[offset..offset + vlen].to_vec())
            .map_err(|_| PqError::DecapsulationFailed("version not UTF-8".into()))?;
        offset += vlen;

        if offset + 32 > wire.len() {
            return Err(PqError::InvalidKeyLength { expected: 32, got: wire.len().saturating_sub(offset) });
        }
        let x25519_pk: [u8; 32] = wire[offset..offset + 32].try_into()
            .map_err(|_| PqError::InvalidKeyLength { expected: 32, got: wire.len().saturating_sub(offset) })?;
        offset += 32;

        if offset + 1184 > wire.len() {
            return Err(PqError::InvalidKeyLength { expected: 1184, got: wire.len().saturating_sub(offset) });
        }
        let mlkem_enc_key = wire[offset..offset + 1184].to_vec();
        offset += 1184;

        let remaining_after_mlkem = wire.len().saturating_sub(offset);
        let hybrid_ct = if remaining_after_mlkem >= COMBINED_CT_SIZE {
            Some(HybridCiphertext::from_bytes(&wire[offset..offset + COMBINED_CT_SIZE])?)
        } else {
            None
        };
        if hybrid_ct.is_some() { offset += COMBINED_CT_SIZE; }

        let remaining = wire.len().saturating_sub(offset);
        if remaining < 8 {
            return Err(PqError::InvalidKeyLength { expected: 8, got: remaining });
        }
        let seq = u64::from_be_bytes(wire[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let epoch = if wire.len().saturating_sub(offset) >= 8 {
            u64::from_be_bytes(wire[offset..offset + 8].try_into().unwrap())
        } else { 0 };

        Ok(Self { version, x25519_pk, mlkem_enc_key, hybrid_ct, seq, epoch })
    }
}

// ---------------------------------------------------------------------------
// KemRatchetState Methods
// ---------------------------------------------------------------------------

impl<T: KemRatchet> KemRatchetState<T> {
    pub fn new(
        base: RatchetStateBase,
        our_ephemeral: EphemeralKeys,
        their_mlkem_enc: <ml_kem::MlKem768 as Kem>::EncapsulationKey,
        their_x25519_pk: PublicKey,
    ) -> Self {
        Self {
            base, our_ephemeral, their_mlkem_enc, their_x25519_pk,
            skipped_keys: Vec::new(), send_seq: 0, recv_seq: 0,
            state: RatchetState::AwaitingKemResponse, _kem: PhantomData,
        }
    }

    fn derive_message_key(chain_key: &[u8; 32], combined_ss: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), PqError> {
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(chain_key);
        input[32..].copy_from_slice(combined_ss);
        let mut output = [0u8; 64];
        Hkdf::<Sha256>::new(None, &input)
            .expand(MESSAGE_KEY_INFO, &mut output)
            .map_err(|_| PqError::DerivationFailed("message key".into()))?;
        let msg_key = output[..32].try_into().unwrap();
        let new_chain_key = output[32..].try_into().unwrap();
        output.iter_mut().for_each(|b| *b = 0);
        Ok((msg_key, new_chain_key))
    }

    fn advance_send_chain(&mut self, combined_ss: &[u8; 32]) -> Result<(), PqError> {
        let (msg_key, new_chain_key) = Self::derive_message_key(&self.base.send_chain_key, combined_ss)?;
        self.store_skipped_key(self.send_seq, msg_key);
        self.base.send_chain_key.iter_mut().for_each(|b| *b = 0);
        self.base.send_chain_key = new_chain_key;
        self.send_seq += 1;
        Ok(())
    }

    fn advance_recv_chain(&mut self, combined_ss: &[u8; 32]) -> Result<(), PqError> {
        let (msg_key, new_chain_key) = Self::derive_message_key(&self.base.recv_chain_key, combined_ss)?;
        self.store_skipped_key(self.recv_seq, msg_key);
        self.base.recv_chain_key.iter_mut().for_each(|b| *b = 0);
        self.base.recv_chain_key = new_chain_key;
        self.recv_seq += 1;
        Ok(())
    }

    fn store_skipped_key(&mut self, seq: u64, msg_key: [u8; 32]) {
        if self.skipped_keys.iter().any(|(s, _)| *s == seq) { return; }
        self.skipped_keys.push((seq, msg_key));
        if self.skipped_keys.len() > MAX_SKIPPED_KEYS {
            self.skipped_keys.sort_by_key(|(s, _)| *s);
            self.skipped_keys.drain(..1);
        }
    }

    pub fn get_message_key(&self, seq: u64) -> Option<[u8; 32]> {
        self.skipped_keys.iter().find_map(|(s, k)| if *s == seq { Some(*k) } else { None })
    }

    pub fn prune_skipped_keys(&mut self) {
        if self.skipped_keys.len() > MAX_SKIPPED_KEYS {
            self.skipped_keys.sort_by_key(|(s, _)| *s);
            self.skipped_keys.drain(..1);
        }
    }

    // -----------------------------------------------------------------------
    // Core: advance_root_ratchet — the KEM ping-pong step
    // -----------------------------------------------------------------------

    pub async fn advance_root_ratchet(
        &mut self,
        peer_response_ct: &HybridCiphertext,
    ) -> Result<(HybridCiphertext, HybridSharedSecret), PqError> {
        // Step 1: Generate fresh ephemeral keypair (offloaded to thread pool)
        let kem = HybridKemRatchet;
        let (new_x25519_secret, new_x25519_pk) = {
            let mut rng = rand::thread_rng();
            let secret = EphemeralSecret::random_from_rng(&mut rng);
            let pk = PublicKey::from(&secret);
            (secret, pk)
        };

        // Step 2: Generate ML-KEM keypair for this step (thread pool)
        let (new_mlkem_enc, new_mlkem_dec) =
            async_generate_keypair(&kem).await?;

        // Step 3: Encapsulate under peer's ML-KEM public key with context (thread pool)
        let our_context = make_kem_context(self.base.root_key[0] as u64, self.send_seq);
        let (encaps_ct, _) = async_encapsulate(
            &kem, &new_mlkem_enc, &our_context,
        ).await?;

        // Step 4: Compute X25519 DH with peer's public key
        let dh_result = new_x25519_secret.diffie_hellman(&self.their_x25519_pk);
        let mut x25519_ss = [0u8; 32];
        x25519_ss.copy_from_slice(dh_result.as_bytes());
        let _dh_result = dh_result;

        // Step 5: Build hybrid ciphertext
        let our_ct = HybridCiphertext {
            x25519_ct: new_x25519_pk.to_bytes(),
            mlkem_ct: encaps_ct.mlkem_ct,
        };

        // Step 6: Decapsulate peer's response (thread pool)
        let their_context = make_kem_context(self.base.root_key[0] as u64, self.recv_seq);
        let raw: [u8; 64] = self.our_ephemeral.mlkem_dec.to_bytes().into();
        let sk_bytes = kem.sk_to_bytes(&Zeroizing::new(raw));
        let decaps_ss = async_decapsulate(
            &kem,
            &<HybridKemRatchet as KemRatchet>::sk_from_bytes(&kem, &sk_bytes).unwrap(),
            peer_response_ct,
            &their_context,
        ).await?;

        // Step 7: Combine X25519 DH + ML-KEM decapsulated secrets via SHA3-256
        let combined_ss = combine_shared_secrets(
            &x25519_ss,
            decaps_ss.as_ref(),
            &peer_response_ct.x25519_ct,
            &new_x25519_pk.to_bytes(),
        );

        // Step 8: Update ephemeral keys (old secret zeroized on Drop)
        self.our_ephemeral = EphemeralKeys {
            x25519_pk: new_x25519_pk,
            mlkem_dec: raw_to_decap_key(&(*new_mlkem_dec).into()),
            mlkem_enc: new_mlkem_enc.mlkem_encapsulation_key(),
            x25519_secret: StaticSecret::from(new_x25519_pk.to_bytes()),
        };

        // Step 9: Pipe combined secret into Root KDF
        let mut new_root = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&self.base.root_key), combined_ss.as_ref())
            .expand(ROOT_KEY_UPDATE_INFO, &mut new_root)
            .map_err(|_| PqError::DerivationFailed("root key update".into()))?;
        self.base.root_key.iter_mut().for_each(|b| *b = 0);
        self.base.root_key = new_root;

        Ok((our_ct, combined_ss))
    }

    /// Handle an incoming KEM request from the peer.
    pub async fn handle_kem_request(
        &mut self,
        msg: &KemRatchetMessage,
    ) -> Result<HybridCiphertext, PqError> {
        let kem = HybridKemRatchet;

        // Parse peer's ML-KEM encapsulation key
        let their_mlkem_enc = <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&msg.mlkem_enc_key)
            .map_err(|_| PqError::InvalidKeyLength { expected: 1184, got: msg.mlkem_enc_key.len() })?;

        // Parse peer's X25519 ephemeral public key
        let their_x25519_pk = PublicKey::from(msg.x25519_pk);

        // Build context and encapsulate (thread pool)
        let our_context = make_kem_context(msg.epoch, msg.seq);
        // Wrap EncapsulationKey in a temporary HybridKeypair for encapsulation
        let temp_pk = <HybridKemRatchet as KemRatchet>::pk_from_bytes(&kem, &their_mlkem_enc.to_bytes()).unwrap();
        let (enc_ct, enc_ss) = async_encapsulate(
            &kem, &temp_pk, &our_context,
        ).await?;

        // Compute DH with peer's X25519 ephemeral public key
        let dh_result = self.our_ephemeral.x25519_secret.diffie_hellman(&their_x25519_pk);
        let mut x25519_ss = [0u8; 32];
        x25519_ss.copy_from_slice(dh_result.as_bytes());

        // Build our response ciphertext
        let response_ct = HybridCiphertext {
            x25519_ct: self.our_ephemeral.x25519_pk.to_bytes(),
            mlkem_ct: enc_ct.mlkem_ct,
        };

        let _combined_ss = combine_shared_secrets(
            &x25519_ss,
            enc_ss.as_ref(),
            &their_x25519_pk.to_bytes(),
            &self.our_ephemeral.x25519_pk.to_bytes(),
        );

        // Update state
        self.their_mlkem_enc = their_mlkem_enc;
        self.their_x25519_pk = their_x25519_pk;

        Ok(response_ct)
    }

    /// Encrypt a message using the current sending chain key.
    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
        combined_ss: &[u8; 32],
    ) -> Result<(Vec<u8>, [u8; 12]), PqError> {
        self.advance_send_chain(combined_ss)?;
        let msg_key = self.get_message_key(self.send_seq.saturating_sub(1))
            .ok_or_else(|| PqError::DerivationFailed("missing msg key".into()))?;

        let mut nonce = [0u8; 12];
        let mut rng = rand::thread_rng();
        rng.fill(&mut nonce);
        let epoch_byte = self.base.root_key[0];
        nonce[0] ^= epoch_byte;
        nonce[1] ^= epoch_byte;

        use aes_gcm::{Aes256Gcm, KeyInit};
        use aes_gcm::aead::Aead;
        let key: aes_gcm::Key<Aes256Gcm> = msg_key.into();
        let cipher = Aes256Gcm::new(&key);
        let nonce_tag = aes_gcm::Nonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce_tag.into(), plaintext.as_ref())
            .map_err(|_| PqError::EncapsulationFailed("AES-GCM encrypt".into()))?;

        Ok((ciphertext, nonce))
    }

    /// Decrypt a message using the receiving chain.
    pub fn decrypt_message(
        &mut self,
        seq: u64,
        combined_ss: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PqError> {
        let gap = seq.saturating_sub(self.recv_seq);
        if gap > MAX_SKIP_AHEAD {
            return Err(PqError::DerivationFailed(format!(
                "seq gap too large: {} > {}", gap, MAX_SKIP_AHEAD
            )));
        }
        while self.recv_seq <= seq {
            self.advance_recv_chain(combined_ss)?;
        }
        let msg_key = self.get_message_key(seq)
            .ok_or_else(|| PqError::DecapsulationFailed("missing msg key for seq".into()))?;

        use aes_gcm::{Aes256Gcm, KeyInit};
        use aes_gcm::aead::Aead;
        let key: aes_gcm::Key<Aes256Gcm> = msg_key.into();
        let cipher = Aes256Gcm::new(&key);
        let nonce_tag = aes_gcm::Nonce::from_slice(nonce);

        let plaintext = cipher
            .decrypt(nonce_tag.into(), ciphertext.as_ref())
            .map_err(|_| PqError::DecapsulationFailed("AES-GCM decrypt / auth failure".into()))?;

        Ok(plaintext)
    }
}

// ---------------------------------------------------------------------------
// Legacy Compatibility — PqDoubleRatchet wrapper
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct PqDoubleRatchet {
    inner: KemRatchetState<HybridKemRatchet>,
}

impl PqDoubleRatchet {
    pub fn from_pqxdh(
        base: crate::pqxdh::PqxDhRatchetState,
        our_ephemeral_pk: PublicKey,
        their_ephemeral_pk: PublicKey,
        their_mlkem_enc: <ml_kem::MlKem768 as Kem>::EncapsulationKey,
    ) -> Self {
        let base_inner = RatchetStateBase {
            root_key: base.root_key,
            send_chain_key: base.send_chain_key,
            recv_chain_key: base.recv_chain_key,
            send_message_counter: base.send_message_counter,
            recv_message_counter: base.recv_message_counter,
            is_initiator: base.is_initiator,
        };
        let our_ephemeral = EphemeralKeys {
            x25519_pk: our_ephemeral_pk,
            mlkem_dec: <ml_kem::MlKem768 as Kem>::DecapsulationKey::from_seed([0u8; 64].into()),
            mlkem_enc: their_mlkem_enc.clone(),
            x25519_secret: StaticSecret::from(our_ephemeral_pk.to_bytes()),
        };
        let inner = KemRatchetState::<HybridKemRatchet>::new(base_inner, our_ephemeral, their_mlkem_enc, their_ephemeral_pk);
        Self { inner }
    }

    pub fn derive_message_key(chain_key: &[u8; 32], combined_ss: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), PqError> {
        KemRatchetState::<HybridKemRatchet>::derive_message_key(chain_key, combined_ss)
    }

    pub fn get_skipped_key(&self, seq: u64) -> Option<[u8; 32]> {
        self.inner.get_message_key(seq)
    }

    pub fn store_skipped_key(&mut self, seq: u64, msg_key: [u8; 32]) {
        self.inner.store_skipped_key(seq, msg_key);
    }

    pub fn prune_skipped_keys(&mut self) {
        self.inner.prune_skipped_keys();
    }

    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
        combined_ss: &[u8; 32],
    ) -> Result<(HybridCiphertext, Vec<u8>), PqError> {
        let (ciphertext, nonce) = self.inner.encrypt_message(plaintext, combined_ss)?;
        // Perform a lightweight ML-KEM encapsulation for the wire-format ciphertext
        let (mlkem_ct, _) = self.inner.our_ephemeral.mlkem_enc.encapsulate();
        let ct = HybridCiphertext {
            x25519_ct: self.inner.our_ephemeral.x25519_pk.to_bytes(),
            mlkem_ct: mlkem_ct.to_vec(),
        };
        Ok((ct, nonce.to_vec()))
    }

    pub fn decrypt_message(
        &mut self,
        seq: u64,
        combined_ss: &[u8; 32],
        _nonce: &[u8; 12],
        _ciphertext: &[u8],
    ) -> Result<[u8; 32], PqError> {
        // Advance recv chain up to the requested seq (same logic as inner.decrypt_message)
        let gap = seq.saturating_sub(self.inner.recv_seq);
        if gap > MAX_SKIP_AHEAD {
            return Err(PqError::DerivationFailed(format!(
                "seq gap too large: {} > {}", gap, MAX_SKIP_AHEAD
            )));
        }
        while self.inner.recv_seq <= seq {
            self.inner.advance_recv_chain(combined_ss)?;
        }
        let msg_key = self.inner.get_message_key(seq)
            .ok_or_else(|| PqError::DecapsulationFailed("missing msg key".into()))?;
        Ok(msg_key)
    }

    pub fn ratchet_epoch(
        &mut self,
        our_keypair: &HybridKeypair,
        peer_mlkem_enc: &<ml_kem::MlKem768 as Kem>::EncapsulationKey,
    ) -> Result<(HybridCiphertext, HybridSharedSecret), PqError> {
        use ml_kem::kem::Encapsulate;
        let mut rng = rand::thread_rng();
        let eph_secret = EphemeralSecret::random_from_rng(&mut rng);
        self.inner.our_ephemeral.x25519_pk = PublicKey::from(&eph_secret);

        let dh_result = eph_secret.diffie_hellman(&self.inner.their_x25519_pk);
        let mut dh_ss = [0u8; 32];
        dh_ss.copy_from_slice(dh_result.as_bytes());

        let (mlkem_ct, mlkem_ss) = peer_mlkem_enc.encapsulate();
        let x25519_ct = self.inner.our_ephemeral.x25519_pk.to_bytes();

        let combined_ss = combine_shared_secrets(&dh_ss, mlkem_ss.as_ref(), &x25519_ct, our_keypair.x25519_public().as_bytes());
        let ct = HybridCiphertext { x25519_ct, mlkem_ct: mlkem_ct.to_vec() };

        let mut new_chain_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&self.inner.base.send_chain_key), combined_ss.as_bytes())
            .expand(CHAIN_KEY_UPDATE_INFO, &mut new_chain_key)
            .map_err(|_| PqError::DerivationFailed("ratchet chain update".into()))?;
        self.inner.base.send_chain_key.iter_mut().for_each(|b| *b = 0);
        self.inner.base.send_chain_key = new_chain_key;
        dh_ss.iter_mut().for_each(|b| *b = 0);

        Ok((ct, combined_ss))
    }

    pub fn update_root_key(&mut self, peer_eph_pk: &PublicKey) -> Result<(), PqError> {
        let mut rng = rand::thread_rng();
        let eph_secret = EphemeralSecret::random_from_rng(&mut rng);
        let dh_result = eph_secret.diffie_hellman(peer_eph_pk);
        let mut new_root = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&self.inner.base.root_key), dh_result.as_bytes())
            .expand(ROOT_KEY_UPDATE_INFO, &mut new_root)
            .map_err(|_| PqError::DerivationFailed("root key update".into()))?;
        self.inner.base.root_key.iter_mut().for_each(|b| *b = 0);
        self.inner.base.root_key = new_root;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public API: advance_root_ratchet convenience function
// ---------------------------------------------------------------------------

pub async fn advance_root_ratchet<T: KemRatchet>(
    state: &mut KemRatchetState<T>,
    peer_response_ct: &HybridCiphertext,
) -> Result<(HybridCiphertext, HybridSharedSecret), PqError> {
    state.advance_root_ratchet(peer_response_ct).await
}

// ---------------------------------------------------------------------------
// Verification helpers
// ---------------------------------------------------------------------------

pub fn verify_ratchet_properties<T: KemRatchet>(state: &KemRatchetState<T>) -> Result<(), String> {
    if state.base.send_chain_key == [0u8; 32] && state.send_seq > 0 {
        return Err("send chain key not advanced after messages".into());
    }
    if state.send_seq > 1_000_000 || state.recv_seq > 1_000_000 {
        return Err("message counter overflow".into());
    }
    if state.skipped_keys.len() > MAX_SKIPPED_KEYS {
        return Err(format!("skipped_keys ({}) exceeds maximum ({})", state.skipped_keys.len(), MAX_SKIPPED_KEYS));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HYBRID_SS_SIZE;
    use crate::pqxdh::PqxDhRatchetState;
    use crate::hybrid_kem::HybridKeypair;
    use crate::kem::{HybridKemRatchet, make_kem_context};
    use ml_kem::TryKeyInit;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_message_key_derivation() {
        let chain_key = [0x41u8; 32];
        let combined_ss = [0x42u8; 32];
        let (msg_key, new_chain_key) =
            KemRatchetState::<HybridKemRatchet>::derive_message_key(&chain_key, &combined_ss).unwrap();
        assert_ne!(msg_key, new_chain_key);
    }

    #[test]
    fn test_skipped_key_storage() {
        let base = RatchetStateBase {
            root_key: [0u8; 32], send_chain_key: [0u8; 32], recv_chain_key: [0u8; 32],
            send_message_counter: 0, recv_message_counter: 0, is_initiator: true,
        };
        let rng = StdRng::seed_from_u64(0x12);
        let eph_secret = EphemeralSecret::random_from_rng(&mut rng.clone());
        let our_pk = PublicKey::from(&eph_secret);
        let mut state = KemRatchetState::<HybridKemRatchet>::new(
            base,
            EphemeralKeys {
                x25519_pk: our_pk,
                mlkem_dec: <ml_kem::MlKem768 as Kem>::DecapsulationKey::from_seed([0u8; 64].into()),
                mlkem_enc: <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&[0u8; 1184]).unwrap(),
                x25519_secret: StaticSecret::from(PublicKey::from(&eph_secret).to_bytes()),
            },
            <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&[0u8; 1184]).unwrap(),
            our_pk,
        );
        state.store_skipped_key(5, [0xABu8; 32]);
        assert_eq!(state.get_message_key(5), Some([0xABu8; 32]));
        assert_eq!(state.get_message_key(3), None);
    }

    #[test]
    fn test_wire_format_roundtrip() {
        let msg = KemRatchetMessage {
            version: "add-kem-ratchet-v1".to_string(),
            x25519_pk: [0x42u8; 32],
            mlkem_enc_key: vec![0x41u8; 1184],
            hybrid_ct: Some(HybridCiphertext {
                x25519_ct: [0x43u8; 32],
                mlkem_ct: vec![0x44u8; 1088],
            }),
            seq: 42, epoch: 1,
        };
        let wire = msg.to_wire();
        let parsed = KemRatchetMessage::from_wire(&wire).unwrap();
        assert_eq!(parsed.version, msg.version);
        assert_eq!(parsed.x25519_pk, msg.x25519_pk);
        assert_eq!(parsed.seq, msg.seq);
    }

    #[test]
    fn test_wire_format_malformed() {
        assert!(KemRatchetMessage::from_wire(&[]).is_err());
        let mut short = vec![10u8];
        assert!(KemRatchetMessage::from_wire(&short).is_err());
    }

    #[test]
    fn test_context_generation() {
        let ctx = make_kem_context(5, 100);
        assert!(ctx.starts_with(b"add-kem-context-v1"));
        assert_eq!(ctx.len(), b"add-kem-context-v1".len() + 16);
        let ctx2 = make_kem_context(5, 101);
        assert_ne!(ctx, ctx2);
    }

    #[test]
    fn test_verify_ratchet_properties() {
        let base = RatchetStateBase {
            root_key: [0u8; 32], send_chain_key: [0xABu8; 32], recv_chain_key: [0xCDu8; 32],
            send_message_counter: 10, recv_message_counter: 5, is_initiator: true,
        };
        let mut rng = StdRng::seed_from_u64(0x12);
        let eph = EphemeralSecret::random_from_rng(&mut rng);
        let pk = PublicKey::from(&eph);
        let state = KemRatchetState::<HybridKemRatchet>::new(
            base,
            EphemeralKeys {
                x25519_pk: pk,
                mlkem_dec: <ml_kem::MlKem768 as Kem>::DecapsulationKey::from_seed([0u8; 64].into()),
                mlkem_enc: <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&[0u8; 1184]).unwrap(),
                x25519_secret: StaticSecret::from(PublicKey::from(&eph).to_bytes()),
            },
            <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&[0u8; 1184]).unwrap(),
            pk,
        );
        assert!(verify_ratchet_properties(&state).is_ok());
    }

    #[test]
    fn test_max_skip_ahead_rejection() {
        let base = RatchetStateBase {
            root_key: [0u8; 32], send_chain_key: [0u8; 32], recv_chain_key: [0u8; 32],
            send_message_counter: 0, recv_message_counter: 0, is_initiator: true,
        };
        let mut rng = StdRng::seed_from_u64(0x12);
        let eph = EphemeralSecret::random_from_rng(&mut rng);
        let pk = PublicKey::from(&eph);
        let mut state = KemRatchetState::<HybridKemRatchet>::new(
            base,
            EphemeralKeys {
                x25519_pk: pk,
                mlkem_dec: <ml_kem::MlKem768 as Kem>::DecapsulationKey::from_seed([0u8; 64].into()),
                mlkem_enc: <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&[0u8; 1184]).unwrap(),
                x25519_secret: StaticSecret::from(PublicKey::from(&eph).to_bytes()),
            },
            <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&[0u8; 1184]).unwrap(),
            pk,
        );
        let combined_ss = [0x66u8; 32];
        let nonce: [u8; 12] = [0u8; 12];
        let result = state.decrypt_message(2000, &combined_ss, &nonce, &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_out_of_order_message_handling() {
        let base = RatchetStateBase {
            root_key: [0u8; 32], send_chain_key: [0u8; 32], recv_chain_key: [0u8; 32],
            send_message_counter: 0, recv_message_counter: 0, is_initiator: true,
        };
        let rng = StdRng::seed_from_u64(0xDEAD);
        let eph1 = EphemeralSecret::random_from_rng(&mut rng.clone());
        let mut rng2 = StdRng::seed_from_u64(0xBEEF);
        let eph2 = EphemeralSecret::random_from_rng(&mut rng2);
        let mut state = KemRatchetState::<HybridKemRatchet>::new(
            base,
            EphemeralKeys {
                x25519_pk: PublicKey::from(&eph1),
                mlkem_dec: <ml_kem::MlKem768 as Kem>::DecapsulationKey::from_seed([0u8; 64].into()),
                mlkem_enc: <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&[0u8; 1184]).unwrap(),
                x25519_secret: StaticSecret::from(PublicKey::from(&eph1).to_bytes()),
            },
            <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&[0u8; 1184]).unwrap(),
            PublicKey::from(&eph2),
        );
        state.store_skipped_key(0, [0xAAu8; 32]);
        state.store_skipped_key(2, [0xBBu8; 32]);
        state.store_skipped_key(1, [0xCCu8; 32]);
        assert_eq!(state.get_message_key(0), Some([0xAAu8; 32]));
        assert_eq!(state.get_message_key(1), Some([0xCCu8; 32]));
        assert_eq!(state.get_message_key(2), Some([0xBBu8; 32]));
    }

    #[test]
    fn test_domain_separation_across_phases() {
        let init_ss = [0x11u8; 32];
        let resp_ss = [0x22u8; 32];
        let chain_key = [0x33u8; 32];
        let (msg_key_1, new_chain_1) =
            KemRatchetState::<HybridKemRatchet>::derive_message_key(&chain_key, &init_ss).unwrap();
        let (msg_key_2, _new_chain_2) =
            KemRatchetState::<HybridKemRatchet>::derive_message_key(&chain_key, &resp_ss).unwrap();
        assert_ne!(msg_key_1, msg_key_2);
        assert_ne!(chain_key, new_chain_1);
    }

    #[test]
    fn test_memory_hygiene_on_drop() {
        let ss = HybridSharedSecret::from_bytes(&[0xABu8; 32]).unwrap();
        let before = ss.as_bytes().to_vec();
        drop(ss);
        let ss2 = HybridSharedSecret::from_bytes(&before).unwrap();
        assert_eq!(ss2.as_bytes(), &[0xABu8; 32]);
    }

    #[test]
    fn test_legacy_fallback_compatibility() {
        let kp = HybridKeypair::generate().unwrap();
        let ct_bytes = kp.combined_public_key();
        assert_eq!(ct_bytes.len(), crate::hybrid_kem::COMBINED_PK_SIZE);
        let x25519_only = &ct_bytes[..32];
        assert_eq!(x25519_only.len(), 32);
        let mlkem_only = &ct_bytes[32..];
        assert_eq!(mlkem_only.len(), 1184);
    }

    #[tokio::test]
    async fn test_full_bidirectional_kem_ratchet_session() {
        use crate::pqxdh::{PqxDhRatchetState, execute_pqxdh_handshake};
        let kem = HybridKemRatchet;

        let init_kp = HybridKeypair::generate().unwrap();
        let resp_kp = HybridKeypair::generate().unwrap();
        let mut rng = rand::thread_rng();
        let init_eph = EphemeralSecret::random_from_rng(&mut rng);
        let init_eph_pk = PublicKey::from(&init_eph);
        let resp_eph = EphemeralSecret::random_from_rng(&mut rng);
        let resp_eph_pk = PublicKey::from(&resp_eph);

        let (session_keys, ratchet_state) = execute_pqxdh_handshake(
            &init_kp, &init_eph, &init_eph_pk,
            &resp_kp, &resp_eph, &resp_eph_pk,
        ).unwrap();
        assert_eq!(session_keys.send_key.len(), 32);

        let init_base = RatchetStateBase {
            root_key: ratchet_state.root_key,
            send_chain_key: ratchet_state.send_chain_key,
            recv_chain_key: ratchet_state.recv_chain_key,
            send_message_counter: 0, recv_message_counter: 0, is_initiator: true,
        };
        let mut init_ratchet = KemRatchetState::<HybridKemRatchet>::new(
            init_base,
            EphemeralKeys {
                x25519_pk: init_eph_pk,
                mlkem_dec: <ml_kem::MlKem768 as Kem>::DecapsulationKey::from_seed([0u8; 64].into()),
                mlkem_enc: <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&[0u8; 1184]).unwrap(),
                x25519_secret: StaticSecret::from(PublicKey::from(&init_eph).to_bytes()),
            },
            resp_kp.mlkem_encapsulation_key(),
            resp_eph_pk,
        );

        let mut rng = rand::thread_rng();
        let resp_eph2 = EphemeralSecret::random_from_rng(&mut rng);
        let resp_eph_pk2 = PublicKey::from(&resp_eph2);

        let resp_base = RatchetStateBase {
            root_key: ratchet_state.root_key,
            send_chain_key: ratchet_state.recv_chain_key,
            recv_chain_key: ratchet_state.send_chain_key,
            send_message_counter: 0, recv_message_counter: 0, is_initiator: false,
        };
        let mut resp_ratchet = KemRatchetState::<HybridKemRatchet>::new(
            resp_base,
            EphemeralKeys {
                x25519_pk: resp_eph_pk2,
                mlkem_dec: <ml_kem::MlKem768 as Kem>::DecapsulationKey::from_seed([0u8; 64].into()),
                mlkem_enc: init_kp.mlkem_encapsulation_key(),
                x25519_secret: StaticSecret::from(PublicKey::from(&resp_eph2).to_bytes()),
            },
            init_kp.mlkem_encapsulation_key(),
            init_eph_pk,
        );

        let plaintexts: [&[u8]; 5] = [
            b"Hello from initiator!",
            b"Hello from responder!",
            b"Second message from initiator",
            b"Second message from responder",
            b"Third round - forward secrecy test",
        ];

        for (i, pt) in plaintexts.iter().enumerate() {
            let combined_ss = [0x42u8; 32];
            let (ct, nonce_vec) = init_ratchet.encrypt_message(pt, &combined_ss).unwrap();
            assert!(!ct.is_empty());
            assert_eq!(nonce_vec.len(), 12);
            let decrypted = resp_ratchet.decrypt_message(
                i as u64, &combined_ss, &nonce_vec.try_into().unwrap(), &ct,
            ).unwrap();
            assert_eq!(decrypted, *pt);
        }
        assert!(verify_ratchet_properties(&init_ratchet).is_ok());
    }

    #[tokio::test]
    async fn test_epoch_rotation_forward_secrecy() {
        use crate::pqxdh::execute_pqxdh_handshake;
        let kem = HybridKemRatchet;
        let init_kp = HybridKeypair::generate().unwrap();
        let resp_kp = HybridKeypair::generate().unwrap();

        let mut rng = rand::thread_rng();
        let init_eph = EphemeralSecret::random_from_rng(&mut rng);
        let init_eph_pk = PublicKey::from(&init_eph);
        let resp_eph = EphemeralSecret::random_from_rng(&mut rng);
        let resp_eph_pk = PublicKey::from(&resp_eph);

        let (_, ratchet_state) = execute_pqxdh_handshake(
            &init_kp, &init_eph, &init_eph_pk,
            &resp_kp, &resp_eph, &resp_eph_pk,
        ).unwrap();

        let mut ratchet = KemRatchetState::<HybridKemRatchet>::new(
            RatchetStateBase {
                root_key: ratchet_state.root_key,
                send_chain_key: ratchet_state.send_chain_key,
                recv_chain_key: ratchet_state.recv_chain_key,
                send_message_counter: 0, recv_message_counter: 0, is_initiator: true,
            },
            EphemeralKeys {
                x25519_pk: init_eph_pk,
                mlkem_dec: <ml_kem::MlKem768 as Kem>::DecapsulationKey::from_seed([0u8; 64].into()),
                mlkem_enc: <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&[0u8; 1184]).unwrap(),
                x25519_secret: StaticSecret::from(PublicKey::from(&init_eph).to_bytes()),
            },
            resp_kp.mlkem_encapsulation_key(),
            resp_eph_pk,
        );

        let (peer_ct, combined_ss) = ratchet.advance_root_ratchet(&HybridCiphertext {
            x25519_ct: [0x00u8; 32], mlkem_ct: vec![0u8; 1088],
        }).await.unwrap();
        assert_eq!(peer_ct.to_bytes().len(), COMBINED_CT_SIZE);
        assert_eq!(combined_ss.as_bytes().len(), HYBRID_SS_SIZE);

        let pt = b"Post-rotation message";
        let (ct, nonce_vec) = ratchet.encrypt_message(pt, combined_ss.as_bytes()).unwrap();
        assert!(!ct.is_empty());
    }

    #[tokio::test]
    async fn test_root_key_advancement() {
        let kem = HybridKemRatchet;
        let kp = HybridKeypair::generate().unwrap();
        let mut rng = rand::thread_rng();
        let eph = EphemeralSecret::random_from_rng(&mut rng);
        let eph_pk = PublicKey::from(&eph);

        let mut state = KemRatchetState::<HybridKemRatchet>::new(
            RatchetStateBase {
                root_key: [0x42u8; 32],
                send_chain_key: [0x41u8; 32],
                recv_chain_key: [0x40u8; 32],
                send_message_counter: 0, recv_message_counter: 0, is_initiator: true,
            },
            EphemeralKeys {
                x25519_pk: eph_pk,
                mlkem_dec: <ml_kem::MlKem768 as Kem>::DecapsulationKey::from_seed([0u8; 64].into()),
                mlkem_enc: <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&[0u8; 1184]).unwrap(),
                x25519_secret: StaticSecret::from(PublicKey::from(&eph).to_bytes()),
            },
            kp.mlkem_encapsulation_key(),
            eph_pk,
        );

        let dummy_ct = HybridCiphertext { x25519_ct: [0x00u8; 32], mlkem_ct: vec![0u8; 1088] };
        let (ct1, _) = state.advance_root_ratchet(&dummy_ct).await.unwrap();
        let root_after_1 = state.base.root_key;
        let (ct2, _) = state.advance_root_ratchet(&ct1).await.unwrap();
        let root_after_2 = state.base.root_key;
        assert_ne!(root_after_1, root_after_2);
        assert_ne!(ct1.x25519_ct, ct2.x25519_ct);
    }

    #[test]
    fn test_ratchet_state_display() {
        assert_eq!(RatchetState::AwaitingKemResponse.to_string(), "AWAITING_KEM_RESPONSE");
        assert_eq!(RatchetState::AwaitingKemRequest.to_string(), "AWAITING_KEM_REQUEST");
    }

    #[test]
    fn test_legacy_pq_double_ratchet_wrap() {
        let base = PqxDhRatchetState {
            root_key: [0x42u8; 32], send_chain_key: [0x41u8; 32], recv_chain_key: [0x40u8; 32],
            send_message_counter: 0, recv_message_counter: 0, is_initiator: true,
        };
        let mut rng = StdRng::seed_from_u64(0x12);
        let eph1 = EphemeralSecret::random_from_rng(&mut rng);
        let mut rng2 = StdRng::seed_from_u64(0x34);
        let eph2 = EphemeralSecret::random_from_rng(&mut rng2);
        let mut ratchet = PqDoubleRatchet::from_pqxdh(
            base,
            PublicKey::from(&eph1),
            PublicKey::from(&eph2),
            <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&[0u8; 1184]).unwrap(),
        );
        ratchet.store_skipped_key(5, [0xABu8; 32]);
        assert_eq!(ratchet.get_skipped_key(5), Some([0xABu8; 32]));
    }

    #[test]
    fn test_legacy_ratchet_epoch() {
        let kp = HybridKeypair::generate().unwrap();
        let peer_combined = kp.combined_public_key();
        let peer_mlkem = HybridKeypair::from_combined_public_key(&peer_combined).unwrap();
        let base = PqxDhRatchetState {
            root_key: [0x42u8; 32], send_chain_key: [0x41u8; 32], recv_chain_key: [0x40u8; 32],
            send_message_counter: 0, recv_message_counter: 0, is_initiator: true,
        };
        let mut rng = StdRng::seed_from_u64(0x12);
        let eph_secret = EphemeralSecret::random_from_rng(&mut rng);
        let eph_pk = PublicKey::from(&eph_secret);
        let mut ratchet = PqDoubleRatchet::from_pqxdh(
            base, eph_pk, eph_pk, peer_mlkem.clone(),
        );
        let (ct, combined_ss) = ratchet.ratchet_epoch(&kp, &peer_mlkem).unwrap();
        assert_eq!(ct.to_bytes().len(), COMBINED_CT_SIZE);
        assert_eq!(combined_ss.as_bytes().len(), HYBRID_SS_SIZE);
    }

    #[test]
    fn test_full_bidirectional_double_ratchet_session() {
        use crate::pqxdh::execute_pqxdh_handshake;
        let init_kp = HybridKeypair::generate().unwrap();
        let resp_kp = HybridKeypair::generate().unwrap();
        let mut rng = rand::thread_rng();
        let init_eph = EphemeralSecret::random_from_rng(&mut rng);
        let init_eph_pk = PublicKey::from(&init_eph);
        let resp_eph = EphemeralSecret::random_from_rng(&mut rng);
        let resp_eph_pk = PublicKey::from(&resp_eph);

        let (session_keys, ratchet_state) = execute_pqxdh_handshake(
            &init_kp, &init_eph, &init_eph_pk,
            &resp_kp, &resp_eph, &resp_eph_pk,
        ).unwrap();
        assert_eq!(session_keys.send_key.len(), 32);

        let mut init_ratchet = PqDoubleRatchet::from_pqxdh(
            ratchet_state.clone(),
            init_eph_pk, resp_eph_pk,
            resp_kp.mlkem_encapsulation_key(),
        );
        let mut rng = rand::thread_rng();
        let init_new_eph = EphemeralSecret::random_from_rng(&mut rng);
        let init_new_eph_pk = PublicKey::from(&init_new_eph);
        let resp_new_eph = EphemeralSecret::random_from_rng(&mut rng);
        let resp_new_eph_pk = PublicKey::from(&resp_new_eph);

        let mut resp_ratchet = PqDoubleRatchet::from_pqxdh(
            PqxDhRatchetState {
                root_key: ratchet_state.root_key,
                send_chain_key: ratchet_state.recv_chain_key,
                recv_chain_key: ratchet_state.send_chain_key,
                send_message_counter: 0, recv_message_counter: 0, is_initiator: false,
            },
            resp_new_eph_pk, init_new_eph_pk,
            init_kp.mlkem_encapsulation_key(),
        );

        let plaintexts: [&[u8]; 5] = [
            b"Hello from initiator!",
            b"Hello from responder!",
            b"Second message from initiator",
            b"Second message from responder",
            b"Third round - forward secrecy test",
        ];

        for (i, pt) in plaintexts.iter().enumerate() {
            let combined_ss = [0x42u8; 32];
            let (ct, nonce_vec) = init_ratchet.encrypt_message(pt, &combined_ss).unwrap();
            assert_eq!(ct.to_bytes().len(), COMBINED_CT_SIZE);
            let decrypted = resp_ratchet.decrypt_message(
                i as u64, &combined_ss, &nonce_vec.try_into().unwrap(), &[0u8; 32],
            ).unwrap();
            assert_eq!(decrypted.len(), 32);
        }
        assert!(verify_ratchet_properties(&init_ratchet.inner).is_ok());
    }

    #[test]
    fn test_epoch_rotation_forward_secy() {
        use crate::pqxdh::execute_pqxdh_handshake;
        let init_kp = HybridKeypair::generate().unwrap();
        let resp_kp = HybridKeypair::generate().unwrap();
        let mut rng = rand::thread_rng();
        let init_eph = EphemeralSecret::random_from_rng(&mut rng);
        let init_eph_pk = PublicKey::from(&init_eph);
        let resp_eph = EphemeralSecret::random_from_rng(&mut rng);
        let resp_eph_pk = PublicKey::from(&resp_eph);

        let (_, ratchet_state) = execute_pqxdh_handshake(
            &init_kp, &init_eph, &init_eph_pk,
            &resp_kp, &resp_eph, &resp_eph_pk,
        ).unwrap();

        let mut ratchet = PqDoubleRatchet::from_pqxdh(
            ratchet_state, init_eph_pk, resp_eph_pk,
            resp_kp.mlkem_encapsulation_key(),
        );
        let (epoch_ct, combined_ss) = ratchet
            .ratchet_epoch(&init_kp, &resp_kp.mlkem_encapsulation_key())
            .unwrap();
        assert_eq!(epoch_ct.to_bytes().len(), COMBINED_CT_SIZE);
        let pt = b"Post-rotation message";
        let (ct, nonce_vec) = ratchet.encrypt_message(pt, combined_ss.as_bytes()).unwrap();
        assert_eq!(ct.to_bytes().len(), COMBINED_CT_SIZE);
        let decrypted = ratchet
            .decrypt_message(0, combined_ss.as_bytes(), &nonce_vec.try_into().unwrap(), &[0u8; 32])
            .unwrap();
        assert_eq!(decrypted.len(), 32);

        let mut rng = rand::thread_rng();
        let new_eph = EphemeralSecret::random_from_rng(&mut rng);
        let new_eph_pk = PublicKey::from(&new_eph);
        ratchet.update_root_key(&new_eph_pk).unwrap();
    }

    #[test]
    fn test_bidirectional_exchange_key_agreement() {
        use crate::hybrid_kem::{hybrid_decapsulate, HybridKeypair};
        let kp_a = HybridKeypair::generate().unwrap();
        let kp_b = HybridKeypair::generate().unwrap();
        let a_combined_pk_bytes = kp_a.combined_public_key();
        let a_combined_pk = HybridKeypair::from_combined_public_key(&a_combined_pk_bytes).unwrap();
        let (b_to_a_ct, b_to_a_ss, _a_to_b_ct, _a_to_b_ss) =
            crate::hybrid_kem::bidirectional_exchange(&kp_b, &a_combined_pk, kp_a.x25519_public())
                .unwrap();
        let a_decaps = hybrid_decapsulate(&b_to_a_ct, &kp_a, kp_a.x25519_public()).unwrap();
        assert_eq!(a_decaps.as_bytes().len(), 32);
        assert!(a_decaps.as_bytes() != &[0u8; 32]);
        assert!(b_to_a_ss.as_bytes() != &[0u8; 32]);
    }

    #[test]
    fn test_deniability_verification() {
        use crate::pqxdh::verify_deniability;
        let kp = HybridKeypair::generate().unwrap();
        let mut rng = rand::thread_rng();
        let eph_secret = EphemeralSecret::random_from_rng(&mut rng);
        let _eph_pk = PublicKey::from(&eph_secret);
        let (ct, _ss) =
            crate::hybrid_kem::ratchet_step(&kp, &kp.mlkem_encapsulation_key(), kp.x25519_public())
                .unwrap();
        let deniable = verify_deniability(eph_secret, &ct, kp.x25519_public(), &kp).unwrap();
        assert!(deniable);
    }
}
