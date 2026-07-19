//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
//! ML-DSA-87 (FIPS 204) signature operations

use ml_dsa::{
    MlDsa87, Signature as MlDsaSignature, Signer, SigningKey as MlDsaSigningKey, Verifier,
    VerifyingKey as MlDsaVerifyingKey,
};

pub type MlDsa87SigningKey = MlDsaSigningKey<MlDsa87>;
pub type MlDsa87VerifyingKey = MlDsaVerifyingKey<MlDsa87>;
pub type MlDsa87Signature = MlDsaSignature<MlDsa87>;

/// Sign data with ML-DSA-87 signing key
pub fn sign(
    data: &[u8],
    sk: &MlDsa87SigningKey,
) -> Result<MlDsa87Signature, crate::error::PqError> {
    let sig = sk.sign(data);
    Ok(sig)
}

/// Verify ML-DSA-87 signature
pub fn verify(
    data: &[u8],
    sig: &MlDsa87Signature,
    vk: &MlDsa87VerifyingKey,
) -> Result<bool, crate::error::PqError> {
    Ok(vk.verify(data, sig).is_ok())
}
