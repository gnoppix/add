//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix timestamp as f64.
pub fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Generate a random 32-char hex string for message IDs (128 bits of entropy).
/// Re-exported from add_protocol::envelope to avoid duplicate implementations.
pub fn uuid_hex() -> String {
    add_protocol::envelope::uuid_hex()
}

/// Generate a random hex string of the given byte length.
pub fn random_hex(bytes_len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..bytes_len)
        .map(|_| format!("{:02x}", rng.r#gen::<u8>()))
        .collect()
}
