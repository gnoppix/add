//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// Add P2P client node (handshake, NAT traversal, transport).
//-------------------------------------------------------------------------------

pub mod braid_handshake;
pub mod handshake;
pub mod nat;
pub mod peer;
pub mod protocol;
pub mod transport;
pub mod upnp;
pub mod util;

use thiserror::Error;

/// Errors from P2P operations.
#[derive(Debug, Error)]
pub enum P2pError {
    #[error("connection error: {0}")]
    Connection(String),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error("peer error: {0}")]
    Peer(String),

    #[error("NAT traversal error: {0}")]
    Nat(String),

    #[error("timeout")]
    Timeout,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<tokio_tungstenite::tungstenite::Error> for P2pError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        P2pError::Connection(e.to_string())
    }
}
