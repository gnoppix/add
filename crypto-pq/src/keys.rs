//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
//! Post-quantum key pair management

use add_crypto::kyber::{
    MlKem1024EncapsulationKey,
    MlKem1024DecapsulationKey,
    MlKem1024Keypair,
    MlKem1024Ciphertext,
    MlKem1024SharedSecret,
};

use ml_dsa::{MlDsa87, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey, 
             Signature as MlDsaSignature, Signer, Verifier, KeyExport, Keypair, Generate};
use ml_kem::MlKem1024;
use rand::rngs::OsRng;
use rand_core::CryptoRng;
pub type MlDsa87SigningKey = MlDsaSigningKey<MlDsa87>;
pub type MlDsa87VerifyingKey = MlDsaVerifyingKey<MlDsa87>;
pub type MlDsa87Signature = MlDsaSignature<MlDsa87>;

/// ML-DSA-87 key pair (for signatures)
#[derive(Debug, Clone)]
pub struct MlDsa87KeyPair {
    sk: MlDsaSigningKey<MlDsa87>,
    vk: MlDsaVerifyingKey<MlDsa87>,
}

impl MlDsa87KeyPair {
    pub fn generate() -> Result<Self, crate::error::PqError> {
        let sk = MlDsaSigningKey::<MlDsa87>::generate();
        let vk = sk.verifying_key().clone();
        Ok(Self { sk, vk })
    }
    
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, crate::error::PqError> {
        use ml_dsa::Seed;
        let seed = Seed::from(*seed);
        let sk = MlDsaSigningKey::<MlDsa87>::from_seed(&seed);
        let vk = sk.verifying_key().clone();
        Ok(Self { sk, vk })
    }
    
    pub fn signing_key(&self) -> &MlDsaSigningKey<MlDsa87> {
        &self.sk
    }
    
    pub fn verifying_key(&self) -> &MlDsaVerifyingKey<MlDsa87> {
        &self.vk
    }
    
    pub fn to_bytes(&self) -> ([u8; 32], Vec<u8>) {
        let sk_seed = self.sk.to_seed();
        let vk_bytes = self.vk.to_bytes().to_vec();
        (*sk_seed.as_ref(), vk_bytes)
    }
}

/// ML-KEM-1024 key pair (for key exchange)
#[derive(Debug, Clone)]
pub struct MlKem1024KeyPair {
    sk: MlKem1024DecapsulationKey,
    pk: MlKem1024EncapsulationKey,
}

impl MlKem1024KeyPair {
    pub fn generate() -> Result<Self, crate::error::PqError> {
        let kp = MlKem1024Keypair::generate()?;
        Ok(Self { sk: kp.dec, pk: kp.enc })
    }
    
    pub fn public_key(&self) -> &MlKem1024EncapsulationKey {
        &self.pk
    }
    
    pub fn secret_key(&self) -> &MlKem1024DecapsulationKey {
        &self.sk
    }
    
    pub fn to_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        (self.sk.to_bytes().to_vec(), self.pk.to_bytes().to_vec())
    }
}

/// Unified post-quantum key pair for both signatures and key exchange
#[derive(Debug, Clone)]
pub struct PqKeyPair {
    pub ml_dsa87: MlDsa87KeyPair,
    pub ml_kem1024: MlKem1024KeyPair,
}

impl PqKeyPair {
    pub fn generate() -> Result<Self, crate::error::PqError> {
        Ok(Self {
            ml_dsa87: MlDsa87KeyPair::generate()?,
            ml_kem1024: MlKem1024KeyPair::generate()?,
        })
    }
}