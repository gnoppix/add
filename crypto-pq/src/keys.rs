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

use add_crypto::kyber::{MlKem1024DecapsulationKey, MlKem1024EncapsulationKey, MlKem1024Keypair};

use ml_dsa::{
    Generate, KeyExport, Keypair, MlDsa87, Signature as MlDsaSignature,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use std::fmt;
pub type MlDsa87SigningKey = MlDsaSigningKey<MlDsa87>;
pub type MlDsa87VerifyingKey = MlDsaVerifyingKey<MlDsa87>;
pub type MlDsa87Signature = MlDsaSignature<MlDsa87>;

/// ML-DSA-87 key pair (for signatures)
/// SECURITY FIX (H1): no `Debug` — the signing key is secret. Manual `Debug`
/// redacts key material so panics/logs never print it.
#[derive(Clone)]
pub struct MlDsa87KeyPair {
    sk: MlDsaSigningKey<MlDsa87>,
    vk: MlDsaVerifyingKey<MlDsa87>,
}

impl fmt::Debug for MlDsa87KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsa87KeyPair")
            .field("sk", &"<secret redacted>")
            .field("vk", &self.vk.to_bytes())
            .finish()
    }
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

    pub fn signing_key(&self) -> MlDsaSigningKey<MlDsa87> {
        self.sk.clone()
    }

    pub fn verifying_key(&self) -> MlDsaVerifyingKey<MlDsa87> {
        self.vk.clone()
    }

    /// Export the seed used to derive this signing key (for persistent storage)
    pub fn to_seed(&self) -> [u8; 32] {
        self.sk.to_seed().into()
    }

    pub fn to_bytes(&self) -> ([u8; 32], Vec<u8>) {
        let sk_seed = self.sk.to_seed();
        let vk_bytes = self.vk.to_bytes().to_vec();
        (*sk_seed.as_ref(), vk_bytes)
    }
}

/// ML-KEM-1024 key pair (for key exchange)
/// SECURITY FIX (H1): no `Debug` — the decapsulation key is secret.
#[derive(Clone)]
pub struct MlKem1024KeyPair {
    sk: MlKem1024DecapsulationKey,
    pk: MlKem1024EncapsulationKey,
}

impl fmt::Debug for MlKem1024KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKem1024KeyPair")
            .field("sk", &"<secret redacted>")
            .field("pk", &"<encapsulation key redacted>")
            .finish()
    }
}

impl MlKem1024KeyPair {
    pub fn generate() -> Result<Self, crate::error::PqError> {
        let kp = MlKem1024Keypair::generate()?;
        Ok(Self {
            sk: kp.dec,
            pk: kp.enc,
        })
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
/// SECURITY FIX (H1): no `Debug` — transitively holds secret keys.
#[derive(Clone)]
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
