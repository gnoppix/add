//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
//! ML-KEM-1024 (FIPS 203) key encapsulation operations
//! Re-export from add-crypto

pub use add_crypto::kyber::{
    MlKem1024EncapsulationKey,
    MlKem1024DecapsulationKey,
    MlKem1024Keypair,
    MlKem1024Ciphertext,
    MlKem1024SharedSecret,
};

use ml_kem::Encapsulate;
use ml_kem::Decapsulate;
use ml_kem::MlKem1024;

/// Encapsulate with ML-KEM-1024 (for post-quantum key exchange)
pub fn encapsulate(
    ek: &MlKem1024EncapsulationKey,
) -> Result<(MlKem1024Ciphertext, MlKem1024SharedSecret), crate::error::PqError> {
    let (ct, ss) = ek.encapsulate();
    Ok((ct, ss))
}

/// Decapsulate with ML-KEM-1024
pub fn decapsulate(
    dk: &MlKem1024DecapsulationKey,
    ct: &MlKem1024Ciphertext,
) -> Result<MlKem1024SharedSecret, crate::error::PqError> {
    let ss = dk.decapsulate(ct);
    Ok(ss)
}