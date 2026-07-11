//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// P2P protocol message types and helpers.
//-------------------------------------------------------------------------------

use serde::{Deserialize, Serialize};

use add_protocol::constants;

/// P2P hello message payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pHello {
    pub public_key: String,
    pub nonce: u64,
    pub pow_bits: u32,
    /// Kyber-768 public key (base64 encoded, 1184 bytes raw)
    /// Used for post-quantum key exchange
    pub kyber_enc_key: String,
    /// SPQR Braid capability flag. When true, the EK is streamed as
    /// `p2p-braid-chunk` frames after the hello instead of (or in addition to)
    /// the inline `kyber_enc_key`.
    pub braid: bool,
    /// SECURITY FIX (M2): Sealed sender identity (optional).
    /// When present, this is a hex-encoded Kyber-768 ciphertext that encapsulates
    /// `{sender_nid}|{sender_fp}|{sender_kyber_fp}` under the recipient's
    /// Kyber public key (obtained from DHT/contact lookup).
    /// The recipient decapsulates this with their Kyber private key to learn
    /// who is connecting. The `public_key` field is then a one-time commitment
    /// (SHA-256 of the ephemeral key) rather than the real GPG fingerprint.
    pub sealed_identity: String,
}

/// P2P hello-ack message payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pHelloAck {
    pub public_key: String,
    pub nonce: u64,
    pub pow_bits: u32,
    /// SECURITY FIX (M6): Server-generated challenge to make PoW
    /// unique per connection, preventing replay of the same PoW
    /// across multiple connections.
    pub server_challenge: String,
    /// Kyber-768 public key (base64 encoded)
    /// Used for post-quantum key exchange
    pub kyber_enc_key: String,
    /// SPQR Braid capability flag (mirrors the initiator's hello).
    pub braid: bool,
}

/// P2P message payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pMessage {
    pub seq: i64,
    pub ciphertext: String,
    pub msg_hash: String,
    /// Optional auto-destruct timer (e.g., "2h", "12h", "24h", "48h", "5d", "7d", "14d")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
}

/// P2P ack payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pAck {
    pub seq: i64,
    pub msg_hash: String,
}

/// Build a p2p-hello wire envelope.
/// SECURITY FIX (C1): Include Kyber public key for post-quantum key exchange.
/// SECURITY FIX (M2): Include sealed_identity for sender anonymity.
pub fn build_p2p_hello(
    public_key_b64: &str,
    nonce: u64,
    pow_bits: u32,
    kyber_enc_key_b64: &str,
    sealed_identity: &str,
) -> add_protocol::envelope::WireEnvelope {
    use add_protocol::envelope::WireEnvelope;
    WireEnvelope {
        msg_type: constants::MSG_P2P_HELLO.to_string(),
        payload: serde_json::json!({
            "public_key": public_key_b64,
            "nonce": nonce,
            "pow_bits": pow_bits,
            "kyber_enc_key": kyber_enc_key_b64,
            "sealed_identity": sealed_identity,
            "braid": true,
        }),
        msg_id: crate::util::uuid_hex(),
        ts: crate::util::now_unix(),
        sig: String::new(),
    }
}

/// Build a signed p2p-hello wire envelope.
/// SECURITY FIX (C1): Include Kyber public key for post-quantum key exchange.
/// SECURITY FIX (C2): Sign the hello to authenticate the initiator.
/// SECURITY FIX (M2): Include sealed_identity for sender anonymity.
/// `sender_verifying_key` (ML-DSA-87 VK base64) is embedded in the payload so
/// the responder can verify the signature without a DHT round-trip.
pub fn build_p2p_hello_signed(
    public_key_b64: &str,
    nonce: u64,
    pow_bits: u32,
    kyber_enc_key_b64: &str,
    sealed_identity: &str,
    signature: &str,
    sender_verifying_key: &str,
) -> add_protocol::envelope::WireEnvelope {
    let mut env = build_p2p_hello(public_key_b64, nonce, pow_bits, kyber_enc_key_b64, sealed_identity);
    if !sender_verifying_key.is_empty() {
        env.payload["sender_verifying_key"] = serde_json::Value::String(sender_verifying_key.to_string());
    }
    env.sig = signature.to_string();
    env
}

/// Build a p2p-hello-ack wire envelope.
///
/// SECURITY FIX (C3): hello-ack messages should be signed to prevent
/// MITM injection of fake handshake completions. Use `build_p2p_hello_ack_signed`
/// with a GPG signature in production.
/// SECURITY FIX (M6): Includes a server_challenge to prevent PoW replay.
/// SECURITY FIX (C1): Includes Kyber public key for post-quantum key exchange.
pub fn build_p2p_hello_ack(
    public_key_b64: &str,
    nonce: u64,
    pow_bits: u32,
    server_challenge: &str,
    kyber_enc_key_b64: &str,
) -> add_protocol::envelope::WireEnvelope {
    use add_protocol::envelope::WireEnvelope;
    WireEnvelope {
        msg_type: constants::MSG_P2P_HELLO_ACK.to_string(),
        payload: serde_json::json!({
            "public_key": public_key_b64,
            "nonce": nonce,
            "pow_bits": pow_bits,
            "server_challenge": server_challenge,
            "kyber_enc_key": kyber_enc_key_b64,
            "braid": true,
        }),
        msg_id: crate::util::uuid_hex(),
        ts: crate::util::now_unix(),
        sig: String::new(),
    }
}

/// Build a signed p2p-hello-ack wire envelope.
///
/// SECURITY FIX (C3): The signature authenticates the responder, preventing
/// an active MITM from injecting a fake hello-ack and hijacking the session.
pub fn build_p2p_hello_ack_signed(
    public_key_b64: &str,
    nonce: u64,
    pow_bits: u32,
    server_challenge: &str,
    kyber_enc_key_b64: &str,
    signature: &str,
    sender_verifying_key: &str,
) -> add_protocol::envelope::WireEnvelope {
    let mut env = build_p2p_hello_ack(public_key_b64, nonce, pow_bits, server_challenge, kyber_enc_key_b64);
    if !sender_verifying_key.is_empty() {
        env.payload["sender_verifying_key"] = serde_json::Value::String(sender_verifying_key.to_string());
    }
    env.sig = signature.to_string();
    env
}

/// Build a p2p-message wire envelope.
/// `init_kyber_ct_b64` (optional) carries the initiator's initial Kyber
/// ciphertext so the responder can decapsulate the SAME shared secret the
/// ratchet is seeded with (otherwise both sides encapsulate independently and
/// the chain keys diverge → decryption fails).
pub fn build_p2p_message(
    seq: i64,
    ciphertext_b64: &str,
    msg_hash: &str,
    init_kyber_ct_b64: Option<&str>,
    ttl: Option<&str>,
) -> add_protocol::envelope::WireEnvelope {
    use add_protocol::envelope::WireEnvelope;
    let mut payload = serde_json::json!({
        "seq": seq,
        "ciphertext": ciphertext_b64,
        "msg_hash": msg_hash,
    });
    if let Some(init_ct) = init_kyber_ct_b64 {
        payload["init_kyber_ct"] = serde_json::Value::String(init_ct.to_string());
    }
    if let Some(ttl) = ttl {
        payload["ttl"] = serde_json::json!(ttl);
    }
    WireEnvelope {
        msg_type: constants::MSG_P2P_MESSAGE.to_string(),
        payload,
        msg_id: crate::util::uuid_hex(),
        ts: crate::util::now_unix(),
        sig: String::new(),
    }
}

/// Build a signed p2p-message wire envelope.
///
/// SECURITY FIX (C3): The signature authenticates the sender and protects
/// the sequence number from MITM tampering.
pub fn build_p2p_message_signed(
    seq: i64,
    ciphertext_b64: &str,
    msg_hash: &str,
    signature: &str,
    init_kyber_ct_b64: Option<&str>,
    ttl: Option<&str>,
) -> add_protocol::envelope::WireEnvelope {
    let mut env = build_p2p_message(seq, ciphertext_b64, msg_hash, init_kyber_ct_b64, ttl);
    env.sig = signature.to_string();
    env
}

/// Build a p2p-ack wire envelope.
pub fn build_p2p_ack(seq: i64, msg_hash: &str) -> add_protocol::envelope::WireEnvelope {
    use add_protocol::envelope::WireEnvelope;
    WireEnvelope {
        msg_type: constants::MSG_P2P_ACK.to_string(),
        payload: serde_json::json!({
            "seq": seq,
            "msg_hash": msg_hash,
        }),
        msg_id: crate::util::uuid_hex(),
        ts: crate::util::now_unix(),
        sig: String::new(),
    }
}

/// Build a signed p2p-ack wire envelope.
///
/// SECURITY FIX (C3): The signature prevents MITM from forging acks
/// to suppress delivery confirmations.
pub fn build_p2p_ack_signed(
    seq: i64,
    msg_hash: &str,
    signature: &str,
) -> add_protocol::envelope::WireEnvelope {
    let mut env = build_p2p_ack(seq, msg_hash);
    env.sig = signature.to_string();
    env
}

/// Build a p2p-ping wire envelope.
pub fn build_p2p_ping() -> add_protocol::envelope::WireEnvelope {
    use add_protocol::envelope::WireEnvelope;
    WireEnvelope {
        msg_type: constants::MSG_P2P_PING.to_string(),
        payload: serde_json::json!({}),
        msg_id: crate::util::uuid_hex(),
        ts: crate::util::now_unix(),
        sig: String::new(),
    }
}

/// P2P receipt payload — cryptographic E2E delivery confirmation.
/// The recipient signs this after successfully decrypting a message,
/// proving to the sender that the message was delivered and read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pReceipt {
    pub msg_hash: String,
    /// Epoch timestamp when the message was decrypted.
    pub received_at: f64,
    /// Sequence number of the original message.
    pub seq: i64,
}

/// Build a p2p-receipt wire envelope.
/// The signature is computed over "p2p-receipt:{msg_hash}:{received_at}:{seq}"
/// by the recipient and proves delivery without revealing content.
pub fn build_p2p_receipt(
    msg_hash: &str,
    received_at: f64,
    seq: i64,
    signature: &str,
) -> add_protocol::envelope::WireEnvelope {
    use add_protocol::envelope::WireEnvelope;
    WireEnvelope {
        msg_type: constants::MSG_P2P_RECEIPT.to_string(),
        payload: serde_json::json!({
            "msg_hash": msg_hash,
            "received_at": received_at,
            "seq": seq,
        }),
        msg_id: crate::util::uuid_hex(),
        ts: crate::util::now_unix(),
        sig: signature.to_string(),
    }
}

/// Build a p2p-pong wire envelope.
pub fn build_p2p_pong() -> add_protocol::envelope::WireEnvelope {
    use add_protocol::envelope::WireEnvelope;
    WireEnvelope {
        msg_type: constants::MSG_P2P_PONG.to_string(),
        payload: serde_json::json!({}),
        msg_id: crate::util::uuid_hex(),
        ts: crate::util::now_unix(),
        sig: String::new(),
    }
}
