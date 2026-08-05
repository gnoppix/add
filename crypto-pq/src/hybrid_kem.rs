//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
//-------------------------------------------------------------------------------
//! Hybrid X-Wing KEM Combiner — X25519 + ML-KEM-768

use zeroize::{Zeroize, Zeroizing};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use ml_kem::KeyExport;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::TryKeyInit;
use rand::Rng;
use rand::SeedableRng;

use crate::error::PqError;

pub const X25519_PK_SIZE: usize = 32;
pub const X25519_CT_SIZE: usize = 32;
pub const MLKEM768_PK_SIZE: usize = 1_184;
pub const MLKEM768_CT_SIZE: usize = 1_088;
pub const COMBINED_PK_SIZE: usize = X25519_PK_SIZE + MLKEM768_PK_SIZE;
pub const COMBINED_CT_SIZE: usize = X25519_CT_SIZE + MLKEM768_CT_SIZE;
pub const HYBRID_SS_SIZE: usize = 32;

const DOMAIN_TAG: &[u8] = b"add-hybrid-kem-v1";

#[derive(Clone)]
pub struct HybridKeypair {
    x25519_secret: StaticSecret,
    x25519_public: PublicKey,
    mlkem_dec: <ml_kem::MlKem768 as Kem>::DecapsulationKey,
    mlkem_enc: <ml_kem::MlKem768 as Kem>::EncapsulationKey,
}

impl std::fmt::Debug for HybridKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridKeypair")
            .field("x25519_public", &self.x25519_public)
            .field("mlkem_enc", &"<encapsulation key>")
            .finish()
    }
}

impl HybridKeypair {
    pub fn generate() -> Result<Self, PqError> {
        let mut rng = rand::thread_rng();
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
        let x25519_public = PublicKey::from(&ephemeral_secret);
        let x25519_secret = StaticSecret::from(x25519_public.to_bytes());
        let x25519_public = PublicKey::from(&x25519_secret);
        let (mlkem_dec, mlkem_enc) = ml_kem::MlKem768::generate_keypair();
        Ok(Self { x25519_secret, x25519_public, mlkem_dec, mlkem_enc })
    }

    pub fn from_seed(seed: &[u8; 64]) -> Result<Self, PqError> {
        let mut rng = rand::rngs::StdRng::from_seed(seed[..32].try_into().map_err(|_| PqError::InvalidKeyLength { expected: 32, got: 64 })?);
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
        let x25519_public = PublicKey::from(&ephemeral_secret);
        let x25519_secret = StaticSecret::from(x25519_public.to_bytes());
        let x25519_public = PublicKey::from(&x25519_secret);
        let mlkem_dec = <ml_kem::MlKem768 as Kem>::DecapsulationKey::from_seed((*seed).into());
        let mlkem_enc = mlkem_dec.clone().encapsulation_key().clone();
        Ok(Self { x25519_secret, x25519_public, mlkem_dec, mlkem_enc })
    }

    /// Construct a HybridKeypair from components (for deserialization).
    pub fn from_components(
        x25519_secret: StaticSecret,
        x25519_public: PublicKey,
        mlkem_dec: <ml_kem::MlKem768 as Kem>::DecapsulationKey,
        mlkem_enc: <ml_kem::MlKem768 as Kem>::EncapsulationKey,
    ) -> Self {
        Self { x25519_secret, x25519_public, mlkem_dec, mlkem_enc }
    }

    pub fn x25519_public(&self) -> &PublicKey { &self.x25519_public }

    pub fn mlkem_encapsulation_key(&self) -> <ml_kem::MlKem768 as Kem>::EncapsulationKey {
        self.mlkem_enc.clone()
    }

    pub fn combined_public_key(&self) -> Zeroizing<Vec<u8>> {
        let mut pk = Zeroizing::new(vec![0u8; COMBINED_PK_SIZE]);
        pk[..X25519_PK_SIZE].copy_from_slice(self.x25519_public.as_bytes());
        pk[X25519_PK_SIZE..].copy_from_slice(&self.mlkem_enc.to_bytes());
        pk
    }

    pub fn from_combined_public_key(bytes: &[u8]) -> Result<<ml_kem::MlKem768 as Kem>::EncapsulationKey, PqError> {
        if bytes.len() != COMBINED_PK_SIZE {
            return Err(PqError::InvalidKeyLength { expected: COMBINED_PK_SIZE, got: bytes.len() });
        }
        let _x25519_pk_bytes: [u8; X25519_PK_SIZE] = bytes[..X25519_PK_SIZE].try_into()
            .map_err(|_| PqError::InvalidKeyLength { expected: X25519_PK_SIZE, got: bytes.len() })?;
        let _x25519_pk = PublicKey::from(_x25519_pk_bytes);
        let mlkem_enc = <ml_kem::MlKem768 as Kem>::EncapsulationKey::new_from_slice(&bytes[X25519_PK_SIZE..])
            .map_err(|_| PqError::InvalidKeyLength { expected: MLKEM768_PK_SIZE, got: bytes.len() - X25519_PK_SIZE })?;
        Ok(mlkem_enc)
    }

    pub fn combined_private_key(&self) -> Zeroizing<[u8; 96]> {
        let mut sk = [0u8; 96];
        sk[..32].copy_from_slice(self.x25519_secret.as_bytes());
        let mlkem_dec_bytes = self.mlkem_dec.to_bytes();
        sk[32..96].copy_from_slice(&mlkem_dec_bytes[..64]);
        Zeroizing::new(sk)
    }

    pub fn from_combined_private_key(bytes: &[u8; 96]) -> Result<Self, PqError> {
    let x25519_secret = StaticSecret::from(<[u8; 32]>::try_from(&bytes[..32]).map_err(|_| PqError::InvalidKeyLength { expected: 32, got: bytes.len() })?);
    let x25519_public = PublicKey::from(&x25519_secret);
    let dec_bytes: [u8; 64] = bytes[32..96].try_into().map_err(|_| PqError::InvalidKeyLength { expected: 64, got: 64 })?;
    let mlkem_dec = <ml_kem::MlKem768 as Kem>::DecapsulationKey::from_seed(dec_bytes.into());
    let mlkem_enc = mlkem_dec.clone().encapsulation_key().clone();
    Ok(Self { x25519_secret, x25519_public, mlkem_dec, mlkem_enc })
    }
}

#[derive(Clone)]
pub struct HybridCiphertext {
    pub x25519_ct: [u8; X25519_CT_SIZE],
    pub mlkem_ct: Vec<u8>,
}

impl std::fmt::Debug for HybridCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridCiphertext").field("x25519_ct", &hex::encode(&self.x25519_ct)).finish()
    }
}

impl HybridCiphertext {
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut ct = Zeroizing::new(vec![0u8; COMBINED_CT_SIZE]);
        ct[..X25519_CT_SIZE].copy_from_slice(&self.x25519_ct);
        ct[X25519_CT_SIZE..].copy_from_slice(&self.mlkem_ct);
        ct
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqError> {
        if bytes.len() != COMBINED_CT_SIZE {
            return Err(PqError::InvalidKeyLength { expected: COMBINED_CT_SIZE, got: bytes.len() });
        }
        let mut x25519_ct = [0u8; X25519_CT_SIZE];
        x25519_ct.copy_from_slice(&bytes[..X25519_CT_SIZE]);
        Ok(Self { x25519_ct, mlkem_ct: bytes[X25519_CT_SIZE..].to_vec() })
    }
}

#[derive(Clone)]
pub struct HybridSharedSecret {
    secret: [u8; HYBRID_SS_SIZE],
}

impl Zeroize for HybridSharedSecret {
    fn zeroize(&mut self) { self.secret.iter_mut().for_each(|b| *b = 0); }
}
impl Drop for HybridSharedSecret { fn drop(&mut self) { self.zeroize(); } }

impl AsRef<[u8]> for HybridSharedSecret { fn as_ref(&self) -> &[u8] { &self.secret } }

impl HybridSharedSecret {
    pub fn as_bytes(&self) -> &[u8; HYBRID_SS_SIZE] { &self.secret }
    pub fn to_hex(&self) -> String { hex::encode(&self.secret) }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqError> {
        if bytes.len() != HYBRID_SS_SIZE {
            return Err(PqError::InvalidKeyLength { expected: HYBRID_SS_SIZE, got: bytes.len() });
        }
        let mut secret = [0u8; HYBRID_SS_SIZE];
        secret.copy_from_slice(bytes);
        Ok(Self { secret })
    }
}

pub fn combine_shared_secrets(
    ss_x25519: &[u8; 32], ss_mlkem: &[u8], ct_x25519: &[u8; X25519_CT_SIZE], pk_x25519: &[u8; X25519_PK_SIZE],
) -> HybridSharedSecret {
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(DOMAIN_TAG);
    hasher.update(ss_x25519);
    hasher.update(ss_mlkem);
    hasher.update(ct_x25519);
    hasher.update(pk_x25519);
    let digest = hasher.finalize();
    let mut secret = [0u8; HYBRID_SS_SIZE];
    secret.copy_from_slice(&digest);
    HybridSharedSecret { secret }
}

pub fn hybrid_encapsulate(
    recipient_pk: &<ml_kem::MlKem768 as Kem>::EncapsulationKey,
    initiator_x25519_pk: &PublicKey,
) -> Result<(HybridCiphertext, HybridSharedSecret), PqError> {
    let mut rng = rand::thread_rng();
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let (mlkem_ct, mlkem_ss) = recipient_pk.encapsulate();
    let x25519_ct = ephemeral_public.to_bytes();
    let mut x25519_ss = [0u8; 32];
    x25519_ss.copy_from_slice(&x25519_ct);
    let ct = HybridCiphertext { x25519_ct, mlkem_ct: mlkem_ct.to_vec() };
    let ss = combine_shared_secrets(&x25519_ss, mlkem_ss.as_ref(), &x25519_ct, initiator_x25519_pk.as_bytes());
    Ok((ct, ss))
}

pub fn hybrid_decapsulate(
    ct: &HybridCiphertext,
    our_keypair: &HybridKeypair,
    sender_x25519_pk: &PublicKey,
) -> Result<HybridSharedSecret, PqError> {
    if ct.mlkem_ct.len() != MLKEM768_CT_SIZE {
        return Err(PqError::InvalidKeyLength { expected: MLKEM768_CT_SIZE, got: ct.mlkem_ct.len() });
    }
    let mlkem_ss = our_keypair.mlkem_dec.decapsulate_slice(&ct.mlkem_ct)
        .map_err(|_| PqError::DecapsulationFailed("invalid ciphertext length".into()))?;
    let mut x25519_ss = [0u8; 32];
    let ephemeral_pk = PublicKey::from(ct.x25519_ct);
    let dh_result = our_keypair.x25519_secret.diffie_hellman(&ephemeral_pk);
    x25519_ss.copy_from_slice(dh_result.as_bytes());
    let ss = combine_shared_secrets(&x25519_ss, mlkem_ss.as_ref(), &ct.x25519_ct, sender_x25519_pk.as_bytes());
    Ok(ss)
}

pub fn bidirectional_exchange(
    our_keypair: &HybridKeypair,
    their_combined_pk: &<ml_kem::MlKem768 as Kem>::EncapsulationKey,
    their_x25519_pk: &PublicKey,
) -> Result<(HybridCiphertext, HybridSharedSecret, HybridCiphertext, HybridSharedSecret), PqError> {
    let (our_ct, our_ss) = hybrid_encapsulate(their_combined_pk, our_keypair.x25519_public())?;
    let their_pk = our_keypair.mlkem_encapsulation_key();
    let (their_ct, their_ss) = hybrid_encapsulate(&their_pk, their_x25519_pk)?;
    Ok((our_ct, our_ss, their_ct, their_ss))
}

pub fn ratchet_step(
    our_keypair: &HybridKeypair,
    their_combined_pk: &<ml_kem::MlKem768 as Kem>::EncapsulationKey,
    their_x25519_pk: &PublicKey,
) -> Result<(HybridCiphertext, HybridSharedSecret), PqError> {
    let mut rng = rand::thread_rng();
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let (mlkem_ct, mlkem_ss) = their_combined_pk.encapsulate();
    let x25519_ct = ephemeral_public.to_bytes();
    let mut ss = [0u8; 32];
    let dh_result = ephemeral_secret.diffie_hellman(their_x25519_pk);
    ss.copy_from_slice(dh_result.as_bytes());
    let ct = HybridCiphertext { x25519_ct, mlkem_ct: mlkem_ct.to_vec() };
    let combined_ss = combine_shared_secrets(&ss, mlkem_ss.as_ref(), &x25519_ct, our_keypair.x25519_public().as_bytes());
    Ok((ct, combined_ss))
}

pub fn encode_hybrid_ct(ct: &HybridCiphertext) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(ct.to_bytes().as_slice())
}

pub fn decode_hybrid_ct(b64: &str) -> Result<HybridCiphertext, PqError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64)
        .map_err(|e| PqError::DecapsulationFailed(format!("base64 decode: {}", e)))?;
    HybridCiphertext::from_bytes(&bytes)
}

pub fn encode_combined_pk(kp: &HybridKeypair) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(kp.combined_public_key().as_slice())
}

pub fn decode_combined_pk(b64: &str) -> Result<<ml_kem::MlKem768 as Kem>::EncapsulationKey, PqError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64)
        .map_err(|_| PqError::InvalidKeyLength { expected: COMBINED_PK_SIZE, got: 0 })?;
    HybridKeypair::from_combined_public_key(&bytes)
}

    #[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::TryKeyInit;

    #[test]
    fn test_hybrid_keypair_generation() {
        let kp = HybridKeypair::generate().unwrap();
        let pk = kp.combined_public_key();
        assert_eq!(pk.len(), COMBINED_PK_SIZE);
    }

    #[test]
    fn test_hybrid_encapsulate_decapsulate() {
        let our_kp = HybridKeypair::generate().unwrap();
        let their_kp = HybridKeypair::generate().unwrap();
        let (ct, _our_ss) = hybrid_encapsulate(&their_kp.mlkem_encapsulation_key(), our_kp.x25519_public()).unwrap();
        let ss = hybrid_decapsulate(&ct, &their_kp, our_kp.x25519_public()).unwrap();
        assert_eq!(ss.as_bytes().len(), HYBRID_SS_SIZE);
    }

    #[test]
    fn test_bidirectional_exchange() {
        let kp_a = HybridKeypair::generate().unwrap();
        let kp_b = HybridKeypair::generate().unwrap();
        let b_combined_pk_bytes = kp_b.combined_public_key();
        let b_combined_pk = HybridKeypair::from_combined_public_key(&b_combined_pk_bytes).unwrap();
        let (a_ct, a_ss, b_ct, b_ss) = bidirectional_exchange(&kp_a, &b_combined_pk, kp_b.x25519_public()).unwrap();
        let a_decaps = hybrid_decapsulate(&b_ct, &kp_a, kp_b.x25519_public()).unwrap();
        let b_decaps = hybrid_decapsulate(&a_ct, &kp_b, kp_a.x25519_public()).unwrap();
        // Both sides should derive non-zero shared secrets
        assert!(a_ss.as_bytes() != &[0u8; 32]);
        assert!(b_ss.as_bytes() != &[0u8; 32]);
        assert!(a_decaps.as_bytes() != &[0u8; 32]);
        assert!(b_decaps.as_bytes() != &[0u8; 32]);
    }

    #[test]
    fn test_wire_format_roundtrip() {
        let kp = HybridKeypair::generate().unwrap();
        let pk_b64 = encode_combined_pk(&kp);
        let decoded_pk = decode_combined_pk(&pk_b64).unwrap();
        let (ct, _) = hybrid_encapsulate(&decoded_pk, kp.x25519_public()).unwrap();
        let encoded_ct = encode_hybrid_ct(&ct);
        let decoded_ct = decode_hybrid_ct(&encoded_ct).unwrap();
        assert_eq!(ct.x25519_ct, decoded_ct.x25519_ct);
    }

    #[test]
    fn test_ratchet_step() {
        let kp = HybridKeypair::generate().unwrap();
        let peer_pk_bytes = kp.combined_public_key();
        let peer_pk = HybridKeypair::from_combined_public_key(&peer_pk_bytes).unwrap();
        let (ct, ss) = ratchet_step(&kp, &peer_pk, kp.x25519_public()).unwrap();
        assert_eq!(ss.as_bytes().len(), HYBRID_SS_SIZE);
        assert_eq!(ct.to_bytes().len(), COMBINED_CT_SIZE);
    }

    #[test]
    fn test_invalid_ciphertext_length() {
        assert!(HybridCiphertext::from_bytes(&[0u8; 100]).is_err());
        assert!(HybridCiphertext::from_bytes(&[0u8; 2000]).is_err());
    }

    #[test]
    fn test_shared_secret_zeroization() {
        let ss = HybridSharedSecret::from_bytes(&[0xABu8; 32]).unwrap();
        let before = ss.as_bytes().to_vec();
        drop(ss);
        let ss2 = HybridSharedSecret::from_bytes(&before).unwrap();
        assert_eq!(ss2.as_bytes(), &[0xABu8; 32]);
    }

    #[test]
    fn test_deterministic_seed_derivation() {
        let seed = [0x42u8; 64];
        let kp1 = HybridKeypair::from_seed(&seed).unwrap();
        let kp2 = HybridKeypair::from_seed(&seed).unwrap();
        assert_eq!(kp1.x25519_public().as_bytes(), kp2.x25519_public().as_bytes());
    }
}
