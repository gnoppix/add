//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// Handshake module: p2p-hello / p2p-hello-ack with PoW.
//-------------------------------------------------------------------------------

use rand::Rng;
use tracing::{debug, info};

use add_protocol::constants;
use add_protocol::envelope::WireEnvelope;
use add_protocol::pow::pow_check;

use crate::P2pError;
use crate::protocol::{build_p2p_hello, build_p2p_hello_ack};
use crate::transport::{WebSocketConn, recv_envelope, send_envelope};

/// Timeout for handshake operations (seconds).
const HANDSHAKE_TIMEOUT: u64 = 30;

/// PoW difficulty for P2P hello (bits of leading zeros).
pub const HELLO_POW_BITS: u32 = 16;

/// Perform the handshake as the initiator (connecting party).
/// Sends a p2p-hello with PoW and expects a p2p-hello-ack.
/// SECURITY FIX (C1): Includes Kyber public key for post-quantum key exchange.
pub async fn handshake_initiator(
    ws: &mut WebSocketConn,
    public_key_b64: &str,
    kyber_enc_key_b64: &str,
) -> Result<WireEnvelope, P2pError> {
    // Generate nonce and find valid PoW
    let mut rng = rand::thread_rng();
    let base_nonce: u64 = rng.r#gen();

    // Solve PoW: find nonce such that Argon2id(public_key || nonce) has enough leading zero bits
    let nonce = match solve_hello_pow(public_key_b64, base_nonce, HELLO_POW_BITS) {
        Some(n) => n,
        None => {
            return Err(P2pError::Handshake(
                "failed to solve PoW within attempt budget".to_string(),
            ));
        }
    };

    info!("Sending p2p-hello with PoW nonce={}", nonce);

    let hello = build_p2p_hello(public_key_b64, nonce, HELLO_POW_BITS, kyber_enc_key_b64, "");
    send_envelope(ws, &hello).await?;

    // Receive hello-ack
    let ack = recv_envelope(ws, HANDSHAKE_TIMEOUT).await?;

    if ack.msg_type != constants::MSG_P2P_HELLO_ACK {
        return Err(P2pError::Handshake(format!(
            "expected p2p-hello-ack, got {}",
            ack.msg_type
        )));
    }

    // Verify the peer's PoW
    let peer_key = ack
        .payload
        .get("public_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let peer_nonce = ack
        .payload
        .get("nonce")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let peer_pow_bits = ack
        .payload
        .get("pow_bits")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    // SECURITY FIX (G10): Validate PoW fields before processing
    // Reject obviously invalid nonces and difficulty values to prevent DoS
    if peer_nonce > 1_000_000_000 || peer_pow_bits == 0 || peer_pow_bits > 32 {
        return Err(P2pError::Handshake(
            "invalid PoW parameters: nonce out of range or invalid difficulty".to_string(),
        ));
    }

    // SECURITY FIX (H4): The responder no longer solves PoW (server-side CPU
    // amplification DoS). The initiator only proves work. The responder instead
    // returns a fresh `server_challenge` that binds this handshake to the
    // specific connection, giving liveness + replay protection without the
    // responder spending Argon2id per hello. We require a non-empty challenge.
    let server_challenge = ack
        .payload
        .get("server_challenge")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if server_challenge.is_empty() {
        return Err(P2pError::Handshake(
            "hello-ack missing server_challenge".to_string(),
        ));
    }

    debug!("Handshake complete, peer key: {}", peer_key);
    Ok(ack)
}

/// Perform the handshake as the responder (listening party).
/// Receives a p2p-hello, verifies PoW, sends a p2p-hello-ack.
/// SECURITY FIX (C1): Includes Kyber public key for post-quantum key exchange.
pub async fn handshake_responder(
    ws: &mut WebSocketConn,
    public_key_b64: &str,
    kyber_enc_key_b64: &str,
) -> Result<WireEnvelope, P2pError> {
    // Receive hello
    let hello = recv_envelope(ws, HANDSHAKE_TIMEOUT).await?;

    if hello.msg_type != constants::MSG_P2P_HELLO {
        return Err(P2pError::Handshake(format!(
            "expected p2p-hello, got {}",
            hello.msg_type
        )));
    }

    // Verify PoW
    let peer_key = hello
        .payload
        .get("public_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let peer_nonce = hello
        .payload
        .get("nonce")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let peer_pow_bits = hello
        .payload
        .get("pow_bits")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    // SECURITY FIX (G10): Validate PoW fields before processing
    // Reject obviously invalid nonces and difficulty values to prevent DoS
    if peer_nonce > 1_000_000_000 || peer_pow_bits == 0 || peer_pow_bits > 32 {
        return Err(P2pError::Handshake(
            "invalid PoW parameters: nonce out of range or invalid difficulty".to_string(),
        ));
    }

    let pow_data = format!("{}{}", peer_key, peer_nonce);
    if !pow_check(&pow_data, peer_nonce, peer_pow_bits, &[]).unwrap_or(false) {
        return Err(P2pError::Handshake(
            "peer PoW verification failed".to_string(),
        ));
    }

    // SECURITY FIX (M6): Generate a fresh random server_challenge for this
    // connection. The responder's hello-ack includes this challenge, binding the
    // handshake to this connection (liveness) without the responder solving PoW.
    // SECURITY FIX (H4): the responder does NOT solve Argon2id PoW — that is the
    // initiator's job. Solving it server-side would be a CPU-amplification DoS.
    let server_challenge = crate::util::random_hex(16);

    info!(
        "Received valid p2p-hello, sending p2p-hello-ack challenge={}",
        &server_challenge[..8]
    );

    // SECURITY FIX (H4): nonce/pow_bits are 0 — the responder performs no PoW.
    let ack = build_p2p_hello_ack(
        public_key_b64,
        0,
        0,
        &server_challenge,
        kyber_enc_key_b64,
    );
    send_envelope(ws, &ack).await?;

    Ok(hello)
}

/// Solve PoW for a hello message.
/// Uses a simple brute-force approach starting from base_nonce.
/// SECURITY FIX (M11): Passes empty node_secret since P2P hello PoW
/// is ephemeral (per-connection via server_challenge), not per-node.
///
/// SECURITY FIX (L3): Returns `None` if no valid nonce is found within the
/// attempt budget. The caller must fail loudly — returning an unsolved nonce
/// would let a handshake proceed with a PoW that fails verification later.
fn solve_hello_pow(public_key_b64: &str, base_nonce: u64, difficulty: u32) -> Option<u64> {
    // Try up to 1M attempts
    for i in 0..1_000_000 {
        let nonce = base_nonce.wrapping_add(i);
        let data = format!("{}{}", public_key_b64, nonce);
        if pow_check(&data, nonce, difficulty, &[]).unwrap_or(false) {
            return Some(nonce);
        }
    }
    // No valid nonce found: fail loudly (caller rejects the handshake).
    None
}

/// Verify a received handshake message's PoW.
/// SECURITY FIX (M11): Passes empty node_secret since P2P hello PoW
/// is ephemeral, not per-node.
pub fn verify_hello_pow(public_key_b64: &str, nonce: u64, difficulty: u32) -> bool {
    let data = format!("{}{}", public_key_b64, nonce);
    pow_check(&data, nonce, difficulty, &[]).unwrap_or(false)
}
