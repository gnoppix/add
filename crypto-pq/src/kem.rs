//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
//-------------------------------------------------------------------------------
//! Post-Quantum KEM (Key Encapsulation Mechanism) trait and async wrappers.
//!
//! This module defines the `KemRatchet` trait that abstracts the underlying
//! PQC algorithm, enabling easy swapping between pure ML-KEM, hybrid
//! X25519+ML-KEM (X-Wing), or future KEM constructions.

use zeroize::{Zeroize, Zeroizing};

use crate::error::PqError;
use crate::hybrid_kem::{
    HybridCiphertext, HybridKeypair, HybridSharedSecret,
    COMBINED_CT_SIZE, COMBINED_PK_SIZE, HYBRID_SS_SIZE, MLKEM768_CT_SIZE,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const MAX_KEM_CT_SIZE: usize = COMBINED_CT_SIZE;
pub const MAX_KEM_PK_SIZE: usize = COMBINED_PK_SIZE;

const KEM_CONTEXT_TAG: &[u8] = b"add-kem-context-v1";

// ---------------------------------------------------------------------------
// KemRatchet Trait
// ---------------------------------------------------------------------------

/// Abstract interface for a KEM algorithm used in ratcheting.
pub trait KemRatchet: Send + Sync {
    type PublicKey: std::fmt::Debug + Clone + Send + Sync;
    type DecapKey: Zeroize + Clone + Send + Sync;
    type Ciphertext: Clone + Send + Sync;
    type SharedSecret: AsRef<[u8]> + Zeroize + Clone + Send + Sync;

    fn generate_keypair(&self) -> Result<(Self::PublicKey, Self::DecapKey), PqError>;
    fn encapsulate(&self, pk: &Self::PublicKey, context: &[u8]) -> Result<(Self::Ciphertext, Self::SharedSecret), PqError>;
    fn decapsulate(&self, sk: &Self::DecapKey, ct: &Self::Ciphertext, context: &[u8]) -> Result<Self::SharedSecret, PqError>;
    fn pk_to_bytes(&self, pk: &Self::PublicKey) -> Vec<u8>;
    fn pk_from_bytes(&self, bytes: &[u8]) -> Result<Self::PublicKey, PqError>;
    fn ct_to_bytes(&self, ct: &Self::Ciphertext) -> Vec<u8>;
    fn ct_from_bytes(&self, bytes: &[u8]) -> Result<Self::Ciphertext, PqError>;
    fn sk_to_bytes(&self, sk: &Self::DecapKey) -> Vec<u8>;
    fn sk_from_bytes(&self, bytes: &[u8]) -> Result<Self::DecapKey, PqError>;
}

// ---------------------------------------------------------------------------
// Helper: convert between Zeroizing<[u8;64]> and ml_kem DecapsulationKey
// ---------------------------------------------------------------------------

fn decap_key_to_raw(sk: &Zeroizing<[u8; 64]>) -> [u8; 64] { (**sk).into() }
pub(crate) fn raw_to_decap_key(raw: &[u8; 64]) -> <ml_kem::MlKem768 as ml_kem::kem::Kem>::DecapsulationKey {
    <ml_kem::MlKem768 as ml_kem::kem::Kem>::DecapsulationKey::from_seed((*raw).into())
}
fn seed_to_decap_key(seed: &[u8; 1184]) -> <ml_kem::MlKem768 as ml_kem::kem::Kem>::DecapsulationKey {
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(seed);
    let digest = hasher.finalize();
    let dk_seed: [u8; 64] = {
        let mut arr = [0u8; 64];
        arr[..32].copy_from_slice(&digest);
        arr
    };
    <ml_kem::MlKem768 as ml_kem::kem::Kem>::DecapsulationKey::from_seed(dk_seed.into())
}

// ---------------------------------------------------------------------------
// HybridKemRatchet — concrete implementation for X25519+ML-KEM-768 (X-Wing)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HybridKemRatchet;

impl KemRatchet for HybridKemRatchet {
    type PublicKey = HybridKeypair;
    // Use Zeroizing<[u8;64]> so it satisfies the Zeroize bound on DecapKey
    type DecapKey = Zeroizing<[u8; 64]>;
    type Ciphertext = HybridCiphertext;
    type SharedSecret = HybridSharedSecret;

    fn generate_keypair(&self) -> Result<(Self::PublicKey, Self::DecapKey), PqError> {
        use ml_kem::KeyExport;
        let kp = HybridKeypair::generate()?;
        let enc = kp.mlkem_encapsulation_key();
        let enc_bytes: Vec<u8> = enc.to_bytes().to_vec();
        let seed: [u8; 1184] = enc_bytes.try_into().unwrap_or_else(|_| [0u8; 1184]);
        let dec = seed_to_decap_key(&seed);
        let raw: [u8; 64] = dec.to_bytes().into();
        Ok((kp, Zeroizing::new(raw)))
    }

    fn encapsulate(&self, pk: &Self::PublicKey, context: &[u8]) -> Result<(Self::Ciphertext, Self::SharedSecret), PqError> {
        hybrid_encapsulate_with_context(pk, context)
    }

    fn decapsulate(&self, sk: &Self::DecapKey, ct: &Self::Ciphertext, context: &[u8]) -> Result<Self::SharedSecret, PqError> {
        let raw = decap_key_to_raw(sk);
        let dec = raw_to_decap_key(&raw);
        hybrid_decapsulate_with_context(&dec, ct, context)
    }

    fn pk_to_bytes(&self, pk: &Self::PublicKey) -> Vec<u8> {
        pk.combined_public_key().to_vec()
    }

    fn pk_from_bytes(&self, bytes: &[u8]) -> Result<Self::PublicKey, PqError> {
        use ml_kem::KeyExport;
        let enc = HybridKeypair::from_combined_public_key(bytes)?;
        let x25519_pk_bytes: [u8; 32] = bytes[..32].try_into()
            .map_err(|_| PqError::InvalidKeyLength { expected: 32, got: bytes.len() })?;
        let x25519_pk = x25519_dalek::PublicKey::from(x25519_pk_bytes);
        let x25519_secret = x25519_dalek::StaticSecret::from(x25519_pk_bytes);
        let enc_bytes: Vec<u8> = enc.to_bytes().to_vec();
        let enc_seed: [u8; 1184] = enc_bytes.try_into().unwrap_or_else(|_| [0u8; 1184]);
        let mlkem_dec = seed_to_decap_key(&enc_seed);
        let dec = mlkem_dec.clone();
        let mlkem_enc = dec.encapsulation_key();
        Ok(HybridKeypair::from_components(x25519_secret, x25519_pk, mlkem_dec, mlkem_enc.clone()))
    }

    fn ct_to_bytes(&self, ct: &Self::Ciphertext) -> Vec<u8> {
        ct.to_bytes().to_vec()
    }

    fn ct_from_bytes(&self, bytes: &[u8]) -> Result<Self::Ciphertext, PqError> {
        HybridCiphertext::from_bytes(bytes)
    }

    fn sk_to_bytes(&self, sk: &Self::DecapKey) -> Vec<u8> {
        (**sk).to_vec()
    }

    fn sk_from_bytes(&self, bytes: &[u8]) -> Result<Self::DecapKey, PqError> {
        if bytes.len() != 64 {
            return Err(PqError::InvalidKeyLength { expected: 64, got: bytes.len() });
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        Ok(Zeroizing::new(arr))
    }
}

// ---------------------------------------------------------------------------
// Context-bound encapsulation / decapsulation helpers
// ---------------------------------------------------------------------------

fn hybrid_encapsulate_with_context(
    recipient_pk: &HybridKeypair,
    context: &[u8],
) -> Result<(HybridCiphertext, HybridSharedSecret), PqError> {
    use ml_kem::kem::Encapsulate;
    use sha3::Digest;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let mut rng = rand::thread_rng();
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let enc_key = recipient_pk.mlkem_encapsulation_key();
    let (mlkem_ct, mlkem_ss) = enc_key.encapsulate();
    let x25519_ct = ephemeral_public.to_bytes();

    let dh_result = ephemeral_secret.diffie_hellman(&recipient_pk.x25519_public());
    let mut x25519_ss = [0u8; 32];
    x25519_ss.copy_from_slice(dh_result.as_bytes());

    let mut hasher = sha3::Sha3_256::new();
    hasher.update(KEM_CONTEXT_TAG);
    hasher.update(context);
    hasher.update(&x25519_ss);
    let ss_bytes: &[u8] = mlkem_ss.as_ref();
    hasher.update(ss_bytes);
    hasher.update(&x25519_ct);
    hasher.update(recipient_pk.x25519_public().as_bytes());
    let digest = hasher.finalize();

    let mut secret = [0u8; HYBRID_SS_SIZE];
    secret.copy_from_slice(&digest);

    Ok((HybridCiphertext { x25519_ct, mlkem_ct: mlkem_ct.to_vec() }, HybridSharedSecret::from_bytes(&secret).unwrap()))
}

fn hybrid_decapsulate_with_context(
    sk: &<ml_kem::MlKem768 as ml_kem::kem::Kem>::DecapsulationKey,
    ct: &HybridCiphertext,
    context: &[u8],
) -> Result<HybridSharedSecret, PqError> {
    use ml_kem::kem::Decapsulate;
    use sha3::Digest;
    use x25519_dalek::{PublicKey, StaticSecret};

    if ct.mlkem_ct.len() != MLKEM768_CT_SIZE {
        return Err(PqError::InvalidKeyLength { expected: MLKEM768_CT_SIZE, got: ct.mlkem_ct.len() });
    }

    use ml_kem::KeyExport;
    let mlkem_ss = sk.decapsulate_slice(&ct.mlkem_ct)
        .map_err(|_| PqError::DecapsulationFailed("invalid ciphertext length".into()))?;

    let ephemeral_pk = PublicKey::from(ct.x25519_ct);
    let sk_bytes = sk.to_bytes();
    let x25519_secret = StaticSecret::from(<[u8; 32]>::try_from(&sk_bytes[..32]).map_err(|_| {
        PqError::InvalidKeyLength { expected: 32, got: sk_bytes.len() }
    })?);

    let dh_result = x25519_secret.diffie_hellman(&ephemeral_pk);
    let mut x25519_ss = [0u8; 32];
    x25519_ss.copy_from_slice(dh_result.as_bytes());

    let mut hasher = sha3::Sha3_256::new();
    hasher.update(KEM_CONTEXT_TAG);
    hasher.update(context);
    hasher.update(&x25519_ss);
    let ss_bytes: &[u8] = mlkem_ss.as_ref();
    hasher.update(ss_bytes);
    hasher.update(&ct.x25519_ct);
    hasher.update(&ct.x25519_ct);
    let digest = hasher.finalize();

    let mut secret = [0u8; HYBRID_SS_SIZE];
    secret.copy_from_slice(&digest);

    Ok(HybridSharedSecret::from_bytes(&secret).unwrap())
}

// ---------------------------------------------------------------------------
// Async wrappers — offload heavy crypto to thread pool
// ---------------------------------------------------------------------------

pub async fn async_encapsulate<T: KemRatchet + Clone + 'static>(
    kem: &T,
    pk: &T::PublicKey,
    context: &[u8],
) -> Result<(T::Ciphertext, T::SharedSecret), PqError> {
    let kem = kem.clone();
    let pk = pk.clone();
    let context = context.to_vec();
    tokio::task::spawn_blocking(move || kem.encapsulate(&pk, &context))
        .await
        .map_err(|e| PqError::EncapsulationFailed(format!("spawn_blocking: {}", e)))?
}

pub async fn async_decapsulate<T: KemRatchet + Clone + 'static>(
    kem: &T,
    sk: &T::DecapKey,
    ct: &T::Ciphertext,
    context: &[u8],
) -> Result<T::SharedSecret, PqError> {
    let kem = kem.clone();
    let sk = sk.clone();
    let ct = ct.clone();
    let context = context.to_vec();
    tokio::task::spawn_blocking(move || kem.decapsulate(&sk, &ct, &context))
        .await
        .map_err(|e| PqError::DecapsulationFailed(format!("spawn_blocking: {}", e)))?
}

pub async fn async_generate_keypair<T: KemRatchet + Clone + 'static>(
    kem: &T,
) -> Result<(T::PublicKey, T::DecapKey), PqError> {
    let kem = kem.clone();
    tokio::task::spawn_blocking(move || kem.generate_keypair())
        .await
        .map_err(|e| PqError::KeyGenerationFailed(format!("spawn_blocking: {}", e)))?
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

pub fn make_kem_context(epoch: u64, seq: u64) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(KEM_CONTEXT_TAG.len() + 16);
    ctx.extend_from_slice(KEM_CONTEXT_TAG);
    ctx.extend_from_slice(&epoch.to_be_bytes());
    ctx.extend_from_slice(&seq.to_be_bytes());
    ctx
}

pub fn serialize_keypair<T: KemRatchet>(
    kem: &T, pk: &T::PublicKey, sk: &T::DecapKey,
) -> Zeroizing<Vec<u8>> {
    let pk_bytes = kem.pk_to_bytes(pk);
    let sk_bytes = kem.sk_to_bytes(sk);
    let total = 2 + pk_bytes.len() + 2 + sk_bytes.len();
    let mut buf = Zeroizing::new(Vec::with_capacity(total));
    buf.extend_from_slice(&(pk_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(&pk_bytes);
    buf.extend_from_slice(&(sk_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(&sk_bytes);
    buf
}

pub fn deserialize_keypair<T: KemRatchet>(
    kem: &T, wire: &[u8],
) -> Result<(T::PublicKey, T::DecapKey), PqError> {
    if wire.len() < 4 {
        return Err(PqError::InvalidKeyLength { expected: 4, got: wire.len() });
    }
    let pk_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
    let sk_start = 2 + pk_len + 2;
    if sk_start > wire.len() {
        return Err(PqError::InvalidKeyLength { expected: 4, got: wire.len() });
    }
    let sk_len = u16::from_be_bytes([wire[sk_start - 2], wire[sk_start - 1]]) as usize;
    let sk_end = sk_start + sk_len;
    if sk_end > wire.len() {
        return Err(PqError::InvalidKeyLength { expected: sk_end, got: wire.len() });
    }
    let pk_bytes = &wire[2..sk_start - 2];
    let sk_bytes = &wire[sk_start..sk_end];
    let pk = kem.pk_from_bytes(pk_bytes)?;
    let sk = kem.sk_from_bytes(sk_bytes)?;
    Ok((pk, sk))
}

// ---------------------------------------------------------------------------
// Re-export legacy ML-KEM-1024 helpers from add-crypto
// ---------------------------------------------------------------------------

pub use add_crypto::kyber::{
    MlKem1024Ciphertext, MlKem1024DecapsulationKey, MlKem1024EncapsulationKey, MlKem1024Keypair,
    MlKem1024SharedSecret,
};

pub fn mlkem1024_encapsulate(
    ek: &MlKem1024EncapsulationKey,
) -> Result<(MlKem1024Ciphertext, MlKem1024SharedSecret), crate::error::PqError> {
    use ml_kem::kem::Encapsulate;
    let (ct, ss) = ek.encapsulate();
    Ok((ct, ss))
}

pub fn mlkem1024_decapsulate(
    dk: &MlKem1024DecapsulationKey,
    ct: &MlKem1024Ciphertext,
) -> Result<MlKem1024SharedSecret, crate::error::PqError> {
    use ml_kem::kem::Decapsulate;
    let ss = dk.decapsulate(ct);
    Ok(ss)
}
