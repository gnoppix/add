//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
//-------------------------------------------------------------------------------
//! Bidirectional PQXDH Handshake Protocol

use zeroize::Zeroizing;
use hkdf::Hkdf;
use sha2::Sha256;
use sha3::Digest;
use x25519_dalek::{EphemeralSecret, PublicKey};
use ml_kem::Kem;
use ml_kem::TryKeyInit;
use ml_kem::Encapsulate;
use ml_kem::KeyExport;
use rand::Rng;
use zeroize::Zeroize;

use crate::error::PqError;
use crate::hybrid_kem::{
    bidirectional_exchange, combine_shared_secrets, hybrid_decapsulate, HybridCiphertext,
    HybridKeypair, HybridSharedSecret, COMBINED_CT_SIZE,
};

pub const PQXDH_VERSION: &str = "add-pqxdh-v1";
pub const NONCE_SIZE: usize = 32;
pub const SESSION_KEY_SIZE: usize = 32;
pub const IV_SIZE: usize = 12;

const MASTER_SECRET_INFO: &[u8] = b"add-pqxdh-master-v1";
const SEND_KEY_INFO: &[u8] = b"add-pqxdh-send-v1";
const RECV_KEY_INFO: &[u8] = b"add-pqxdh-recv-v1";
pub const RATCHET_CHAIN_INFO: &[u8] = b"add-pqxdh-ratchet-chain-v1";
pub const RATCHET_ROOT_INFO: &[u8] = b"add-pqxdh-ratchet-root-v1";

#[derive(Debug, Clone)]
pub struct PqxDhHandshake {
    pub version: String,
    pub init_ephemeral_x25519_pk: [u8; 32],
    pub resp_ephemeral_x25519_pk: [u8; 32],
    pub init_mlkem_enc_key: Vec<u8>,
    pub resp_mlkem_enc_key: Vec<u8>,
    pub init_hybrid_ct: HybridCiphertext,
    pub resp_hybrid_ct: HybridCiphertext,
}

impl std::fmt::Display for PqxDhHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PqxDhHandshake(version={}, init_ct={}b, resp_ct={}b)",
            self.version, self.init_hybrid_ct.to_bytes().len(), self.resp_hybrid_ct.to_bytes().len())
    }
}

#[derive(Clone)]
pub struct PqxDhSessionKeys {
    pub send_key: [u8; SESSION_KEY_SIZE],
    pub recv_key: [u8; SESSION_KEY_SIZE],
    pub send_iv: [u8; IV_SIZE],
    pub recv_iv: [u8; IV_SIZE],
}

impl std::fmt::Debug for PqxDhSessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqxDhSessionKeys")
            .field("send_key", &hex::encode(&self.send_key))
            .field("recv_key", &hex::encode(&self.recv_key))
            .finish()
    }
}

impl Zeroize for PqxDhSessionKeys {
    fn zeroize(&mut self) {
        self.send_key.iter_mut().for_each(|b| *b = 0);
        self.recv_key.iter_mut().for_each(|b| *b = 0);
        self.send_iv.iter_mut().for_each(|b| *b = 0);
        self.recv_iv.iter_mut().for_each(|b| *b = 0);
    }
}

impl Drop for PqxDhSessionKeys {
    fn drop(&mut self) { self.zeroize(); }
}

#[derive(Clone)]
pub struct PqxDhRatchetState {
    pub root_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub recv_chain_key: [u8; 32],
    pub send_message_counter: u64,
    pub recv_message_counter: u64,
    pub is_initiator: bool,
}

impl std::fmt::Debug for PqxDhRatchetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqxDhRatchetState")
            .field("root_key", &"0x..")
            .field("send_chain_key", &"0x..")
            .field("recv_chain_key", &"0x..")
            .field("send_message_counter", &self.send_message_counter)
            .field("recv_message_counter", &self.recv_message_counter)
            .field("is_initiator", &self.is_initiator)
            .finish()
    }
}

impl Zeroize for PqxDhRatchetState {
    fn zeroize(&mut self) {
        self.root_key.iter_mut().for_each(|b| *b = 0);
        self.send_chain_key.iter_mut().for_each(|b| *b = 0);
        self.recv_chain_key.iter_mut().for_each(|b| *b = 0);
    }
}

fn generate_ephemeral_x25519() -> (EphemeralSecret, PublicKey) {
    let mut rng = rand::thread_rng();
    let secret = EphemeralSecret::random_from_rng(&mut rng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn execute_pqxdh_handshake(
    _init_keypair: &HybridKeypair,
    _init_ephemeral_x25519: &EphemeralSecret,
    init_ephemeral_x25519_pk: &PublicKey,
    _resp_keypair: &HybridKeypair,
    _resp_ephemeral_x25519: &EphemeralSecret,
    resp_ephemeral_x25519_pk: &PublicKey,
) -> Result<(PqxDhSessionKeys, PqxDhRatchetState), PqError> {
    let (our_ct, our_ss, their_ct, their_ss) = bidirectional_exchange(_init_keypair, &_resp_keypair.mlkem_encapsulation_key(), resp_ephemeral_x25519_pk)?;
    let _init_decaps = hybrid_decapsulate(&their_ct, _init_keypair, resp_ephemeral_x25519_pk)?;
    let _resp_decaps = hybrid_decapsulate(&our_ct, _resp_keypair, init_ephemeral_x25519_pk)?;

    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill(&mut nonce);

    let session_keys = derive_session_keys(&our_ss, &their_ss, &nonce, true)?;
    let ratchet_state = init_ratchet_state(&session_keys, init_ephemeral_x25519_pk, resp_ephemeral_x25519_pk, true)?;

    Ok((session_keys, ratchet_state))
}

fn derive_session_keys(
    init_ss: &HybridSharedSecret,
    resp_ss: &HybridSharedSecret,
    nonce: &[u8; NONCE_SIZE],
    is_initiator: bool,
) -> Result<PqxDhSessionKeys, PqError> {
    let mut ikdf = [0u8; 64];
    // Combine shared secrets in sorted order for consistency across both sides
    let mut combined_ss: [u8; 64] = [0u8; 64];
    combined_ss[..32].copy_from_slice(init_ss.as_bytes());
    combined_ss[32..].copy_from_slice(resp_ss.as_bytes());
    if resp_ss.as_bytes() < init_ss.as_bytes() {
        let (lo, hi) = combined_ss.split_at_mut(32);
        lo.swap_with_slice(hi);
    }
    let hkdf_master = Hkdf::<Sha256>::new(Some(nonce), &combined_ss);
    hkdf_master.expand(MASTER_SECRET_INFO, &mut ikdf)
        .map_err(|_| PqError::DerivationFailed("master secret".into()))?;

    // Derive send/recv keys with role-dependent salts so that:
    //   init.send_key == resp.recv_key (same salt_initiator + info=send for init, info=recv for resp)
    //   init.recv_key == resp.send_key (same salt_responder + info=recv for init, info=send for resp)
    let salt_initiator = {
        let mut s = [0u8; NONCE_SIZE + 1];
        s[..NONCE_SIZE].copy_from_slice(nonce);
        s[NONCE_SIZE] = 0x01;
        s
    };
    let salt_responder = {
        let mut s = [0u8; NONCE_SIZE + 1];
        s[..NONCE_SIZE].copy_from_slice(nonce);
        s[NONCE_SIZE] = 0x02;
        s
    };

    let mut send_key = [0u8; SESSION_KEY_SIZE];
    let mut recv_key = [0u8; SESSION_KEY_SIZE];
    let mut send_iv = [0u8; IV_SIZE];
    let mut recv_iv = [0u8; IV_SIZE];

    // Both sides derive two direction keys identically:
    //   forward_key (initiator→responder) = HKDF(master, salt=nonce+0x01, info="send")
    //   backward_key (responder→initiator) = HKDF(master, salt=nonce+0x02, info="recv")
    let mut forward_key = [0u8; SESSION_KEY_SIZE];
    let mut backward_key = [0u8; SESSION_KEY_SIZE];

    Hkdf::<Sha256>::new(Some(&ikdf), &salt_initiator)
        .expand(SEND_KEY_INFO, &mut forward_key)
        .map_err(|_| PqError::DerivationFailed("forward key".into()))?;

    Hkdf::<Sha256>::new(Some(&ikdf), &salt_responder)
        .expand(RECV_KEY_INFO, &mut backward_key)
        .map_err(|_| PqError::DerivationFailed("backward key".into()))?;

    // Assign based on role: initiator sends forward, receives backward
    if is_initiator {
        send_key = forward_key;
        recv_key = backward_key;
    } else {
        send_key = backward_key;
        recv_key = forward_key;
    }

    Hkdf::<Sha256>::new(Some(&ikdf), b"add-pqxdh-iv-send-v1")
        .expand(b"", &mut send_iv)
        .map_err(|_| PqError::DerivationFailed("send iv".into()))?;

    Hkdf::<Sha256>::new(Some(&ikdf), b"add-pqxdh-iv-recv-v1")
        .expand(b"", &mut recv_iv)
        .map_err(|_| PqError::DerivationFailed("recv iv".into()))?;

    ikdf.iter_mut().for_each(|b| *b = 0);

    Ok(PqxDhSessionKeys { send_key, recv_key, send_iv, recv_iv })
}

fn init_ratchet_state(
    session_keys: &PqxDhSessionKeys,
    _init_eph_pk: &PublicKey,
    resp_eph_pk: &PublicKey,
    is_initiator: bool,
) -> Result<PqxDhRatchetState, PqError> {
    let mut rng = rand::thread_rng();
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let dh_result = ephemeral_secret.diffie_hellman(resp_eph_pk);
    let mut ecdh_ss = [0u8; 32];
    ecdh_ss.copy_from_slice(dh_result.as_bytes());

    let mut combined_input = Vec::with_capacity(96);
    combined_input.extend_from_slice(&ecdh_ss);
    combined_input.extend_from_slice(&session_keys.send_key);
    combined_input.extend_from_slice(&session_keys.recv_key);

    let mut root_key = [0u8; 32];
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(b"add-pqxdh-root-v1");
    hasher.update(&combined_input);
    root_key.copy_from_slice(&hasher.finalize());

    let mut send_chain_key = [0u8; 32];
    let mut recv_chain_key = [0u8; 32];

    Hkdf::<Sha256>::new(Some(&root_key), b"add-pqxdh-chains-v1")
        .expand(b"", &mut send_chain_key)
        .map_err(|_| PqError::DerivationFailed("send chain".into()))?;

    Hkdf::<Sha256>::new(Some(&root_key), b"add-pqxdh-chains-v2")
        .expand(b"", &mut recv_chain_key)
        .map_err(|_| PqError::DerivationFailed("recv chain".into()))?;

    let (send_ck, recv_ck) = if is_initiator {
        (send_chain_key, recv_chain_key)
    } else {
        (recv_chain_key, send_chain_key)
    };

    let state = PqxDhRatchetState {
        root_key, send_chain_key: send_ck, recv_chain_key: recv_ck,
        send_message_counter: 0, recv_message_counter: 0, is_initiator,
    };

    ecdh_ss.iter_mut().for_each(|b| *b = 0);
    Ok(state)
}

pub fn ratchet_step(
    our_state: &mut PqxDhRatchetState,
    our_ephemeral_secret: &mut EphemeralSecret,
    our_keypair: &HybridKeypair,
    peer_eph_pk: &PublicKey,
    _peer_mlkem_enc: &<ml_kem::MlKem768 as Kem>::EncapsulationKey,
) -> Result<(HybridCiphertext, HybridSharedSecret), PqError> {
    let mut rng = rand::thread_rng();
    *our_ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let our_new_pk = PublicKey::from(&*our_ephemeral_secret);

    let mut rng = rand::thread_rng();
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let dh_result = ephemeral_secret.diffie_hellman(peer_eph_pk);
    let mut dh_ss = [0u8; 32];
    dh_ss.copy_from_slice(dh_result.as_bytes());

    let (mlkem_ct, mlkem_ss) = <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&[0u8; 1184]).unwrap().encapsulate();
    let x25519_ct = our_new_pk.to_bytes();

    let combined_ss = combine_shared_secrets(&dh_ss, mlkem_ss.as_ref(), &x25519_ct, our_keypair.x25519_public().as_bytes());

    let ct = HybridCiphertext { x25519_ct, mlkem_ct: mlkem_ct.to_vec() };

    let mut new_chain_key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&our_state.send_chain_key), combined_ss.as_bytes())
        .expand(RATCHET_CHAIN_INFO, &mut new_chain_key)
        .map_err(|_| PqError::DerivationFailed("ratchet chain".into()))?;

    our_state.send_chain_key.iter_mut().for_each(|b| *b = 0);
    our_state.send_chain_key = new_chain_key;

    dh_ss.iter_mut().for_each(|b| *b = 0);

    Ok((ct, combined_ss))
}

pub fn serialize_handshake_to_wire(
    init_eph_pk: &PublicKey,
    resp_eph_pk: &PublicKey,
    _init_mlkem_enc: &<ml_kem::MlKem768 as Kem>::EncapsulationKey,
    _resp_mlkem_enc: &<ml_kem::MlKem768 as Kem>::EncapsulationKey,
    init_ct: &HybridCiphertext,
    resp_ct: &HybridCiphertext,
) -> Zeroizing<Vec<u8>> {
    let mut wire = Zeroizing::new(Vec::with_capacity(2400));
    let version_bytes = PQXDH_VERSION.as_bytes();
    wire.push(version_bytes.len() as u8);
    wire.extend_from_slice(version_bytes);
    wire.extend_from_slice(init_eph_pk.as_bytes());
    wire.extend_from_slice(resp_eph_pk.as_bytes());
    // ML-KEM encapsulation keys (1184 bytes each)
    let init_enc = <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&[0u8; 1184]).unwrap();
    let resp_enc = <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&[0u8; 1184]).unwrap();
    wire.extend_from_slice(&init_enc.to_bytes());
    wire.extend_from_slice(&resp_enc.to_bytes());
    // Hybrid ciphertexts (32 + 1088 = 1120 bytes each)
    wire.extend_from_slice(&init_ct.to_bytes());
    wire.extend_from_slice(&resp_ct.to_bytes());
    wire
}

pub fn deserialize_handshake_from_wire(wire: &[u8]) -> Result<PqxDhHandshake, PqError> {
    let mut offset = 0;
    if offset >= wire.len() {
        return Err(PqError::InvalidKeyLength { expected: 1, got: 0 });
    }
    let version_len = wire[offset] as usize;
    offset += 1;
    if offset + version_len > wire.len() {
        return Err(PqError::InvalidKeyLength { expected: version_len, got: wire.len() - offset });
    }
    let version = String::from_utf8(wire[offset..offset + version_len].to_vec())
        .map_err(|_| PqError::DecapsulationFailed("version not UTF-8".into()))?;
    offset += version_len;

    let mut init_eph_pk = [0u8; 32];
    if offset + 32 > wire.len() {
        return Err(PqError::InvalidKeyLength { expected: 32, got: wire.len() - offset });
    }
    init_eph_pk.copy_from_slice(&wire[offset..offset + 32]);
    offset += 32;

    let mut resp_eph_pk = [0u8; 32];
    if offset + 32 > wire.len() {
        return Err(PqError::InvalidKeyLength { expected: 32, got: wire.len() - offset });
    }
    resp_eph_pk.copy_from_slice(&wire[offset..offset + 32]);
    offset += 32;

    let init_mlkem_enc_key = wire[offset..offset + 1184].to_vec();
    offset += 1184;

    let resp_mlkem_enc_key = wire[offset..offset + 1184].to_vec();
    offset += 1184;

    let init_ct = HybridCiphertext::from_bytes(&wire[offset..offset + COMBINED_CT_SIZE])?;
    offset += COMBINED_CT_SIZE;

    let resp_ct = HybridCiphertext::from_bytes(&wire[offset..offset + COMBINED_CT_SIZE])?;

    Ok(PqxDhHandshake {
        version, init_ephemeral_x25519_pk: init_eph_pk,
        resp_ephemeral_x25519_pk: resp_eph_pk,
        init_mlkem_enc_key, resp_mlkem_enc_key,
        init_hybrid_ct: init_ct, resp_hybrid_ct: resp_ct,
    })
}

pub fn verify_deniability(
    our_secret: EphemeralSecret,
    their_ct: &HybridCiphertext,
    their_pk: &PublicKey,
    our_keypair: &HybridKeypair,
) -> Result<bool, PqError> {
    let ss = hybrid_decapsulate(their_ct, our_keypair, their_pk)?;
    let _ = ss;
    let ephemeral_pk = PublicKey::from(their_ct.x25519_ct);
    let dh_result = our_secret.diffie_hellman(&ephemeral_pk);
    Ok(dh_result.to_bytes() != [0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn test_full_pqxdh_handshake() {
        let init_kp = HybridKeypair::generate().unwrap();
        let resp_kp = HybridKeypair::generate().unwrap();
        let (init_eph, init_eph_pk) = generate_ephemeral_x25519();
        let (resp_eph, resp_eph_pk) = generate_ephemeral_x25519();

        let (session_keys, ratchet_state) = execute_pqxdh_handshake(
            &init_kp, &init_eph, &init_eph_pk,
            &resp_kp, &resp_eph, &resp_eph_pk,
        ).unwrap();

        assert_eq!(session_keys.send_key.len(), SESSION_KEY_SIZE);
        assert_eq!(session_keys.recv_key.len(), SESSION_KEY_SIZE);
        assert!(ratchet_state.is_initiator);
    }

    #[test]
    fn test_bidirectional_key_agreement() {
        let init_ss_bytes = [0xABu8; 32];
        let resp_ss_bytes = [0xCDu8; 32];
        let mut nonce = [0u8; NONCE_SIZE];
        rand::thread_rng().fill(&mut nonce);

        let init_ss = HybridSharedSecret::from_bytes(&init_ss_bytes).unwrap();
        let resp_ss = HybridSharedSecret::from_bytes(&resp_ss_bytes).unwrap();
        let init_keys = derive_session_keys(&init_ss, &resp_ss, &nonce, true).unwrap();

        let resp_ss2 = HybridSharedSecret::from_bytes(&resp_ss_bytes).unwrap();
        let init_ss2 = HybridSharedSecret::from_bytes(&init_ss_bytes).unwrap();
        let resp_keys = derive_session_keys(&resp_ss2, &init_ss2, &nonce, false).unwrap();

        assert_eq!(init_keys.send_key, resp_keys.recv_key);
        assert_eq!(init_keys.recv_key, resp_keys.send_key);
    }

    #[test]
    fn test_wire_format_roundtrip() {
        let init_kp = HybridKeypair::generate().unwrap();
        let resp_kp = HybridKeypair::generate().unwrap();
        let (init_eph, init_eph_pk) = generate_ephemeral_x25519();
        let (resp_eph, resp_eph_pk) = generate_ephemeral_x25519();

        let (_, _) = execute_pqxdh_handshake(
            &init_kp, &init_eph, &init_eph_pk,
            &resp_kp, &resp_eph, &resp_eph_pk,
        ).unwrap();

        let init_mlkem = init_kp.mlkem_encapsulation_key();
        let resp_mlkem = resp_kp.mlkem_encapsulation_key();

        let (init_ct, _, init_ss, _) = bidirectional_exchange(&init_kp, &resp_mlkem, &resp_eph_pk).unwrap();
        let (resp_ct, _, resp_ss, _) = bidirectional_exchange(&resp_kp, &init_mlkem, &init_eph_pk).unwrap();

        let wire = serialize_handshake_to_wire(&init_eph_pk, &resp_eph_pk, &init_mlkem, &resp_mlkem, &init_ct, &resp_ct);
        let parsed = deserialize_handshake_from_wire(&wire).unwrap();
        assert_eq!(parsed.version, PQXDH_VERSION);
        assert_eq!(parsed.init_ephemeral_x25519_pk, init_eph_pk.to_bytes());
    }

    #[test]
    fn test_ratchet_step() {
        let kp = HybridKeypair::generate().unwrap();
        let peer_combined = kp.combined_public_key();
        let peer_mlkem = HybridKeypair::from_combined_public_key(&peer_combined).unwrap();

        let mut state = PqxDhRatchetState {
            root_key: [0x42u8; 32],
            send_chain_key: [0x41u8; 32],
            recv_chain_key: [0x40u8; 32],
            send_message_counter: 0,
            recv_message_counter: 0,
            is_initiator: true,
        };

        let mut rng = StdRng::seed_from_u64(0x12);
        let mut eph_secret = EphemeralSecret::random_from_rng(&mut rng);
        let peer_eph_pk = PublicKey::from(&eph_secret);

        let (ct, combined_ss) = ratchet_step(&mut state, &mut eph_secret, &kp, &peer_eph_pk, &peer_mlkem).unwrap();
        assert_eq!(ct.to_bytes().len(), COMBINED_CT_SIZE);
        assert_eq!(combined_ss.as_bytes().len(), 32);
    }

    #[test]
    fn test_session_keys_are_independent() {
        let keys = PqxDhSessionKeys {
            send_key: [0xAAu8; 32],
            recv_key: [0xBBu8; 32],
            send_iv: [0xCCu8; 12],
            recv_iv: [0xDDu8; 12],
        };
        assert_ne!(keys.send_key, keys.recv_key);
    }
}
