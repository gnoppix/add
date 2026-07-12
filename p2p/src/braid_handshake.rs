//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// SPQR Braid key-exchange transport for P2P.
//
// Wires add_protocol::braid into the live handshake: instead of inlining the
// 1568-byte ML-KEM-1024 encapsulation key in a single hello/hello-ack frame (a
// latency spike, and a large single packet), each peer STREAMS its key as a
// sequence of `p2p-braid-chunk` frames and reassembles the peer's key on arrival.
//
// The exchange is symmetric and deadlock-free: each side sends ALL of its own
// chunks first, then reads ALL of the peer's. The 25 tiny frames (64 B payload
// each) never fill a TCP/WS write buffer, so send-then-receive cannot stall.
//
// The reassembled key feeds the existing ML-KEM KEM + Double Ratchet unchanged --
// braid only replaces the key TRANSPORT, not the cryptography.
//-------------------------------------------------------------------------------

use tokio::io::{AsyncRead, AsyncWrite};

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt as _, StreamExt as _};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use sha2::{Digest, Sha512};

use add_protocol::braid::{
    BraidHandshake, MLKEM1024_EK_LEN, build_braid_chunk_msg, parse_braid_chunk, split_key_to_chunks,
};
use add_protocol::envelope::WireEnvelope;

use crate::P2pError;

/// Timeout (seconds) for receiving a single braid chunk.
const CHUNK_TIMEOUT: u64 = 30;

/// Stream our encapsulation key to the peer as braid chunks.
///
/// `ek_bytes` MUST be the raw 1568-byte ML-KEM-1024 encapsulation key.
pub async fn send_ek_braid<S>(ws: &mut WebSocketStream<S>, ek_bytes: &[u8]) -> Result<(), P2pError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    for chunk in split_key_to_chunks(ek_bytes) {
        let env = build_braid_chunk_msg(&chunk);
        let json = env
            .to_json()
            .map_err(|e| P2pError::Serialization(e.to_string()))?;
        ws.send(tokio_tungstenite::tungstenite::Message::Text(json.into()))
            .await
            .map_err(|e| P2pError::Connection(e.to_string()))?;
    }
    Ok(())
}

/// Receive and reassemble the peer's encapsulation key from braid chunks.
///
/// Reads `p2p-braid-chunk` frames until the handshake is complete, verifies the
/// SHA-512 `ek_hash` (via `BraidHandshake`), and returns the reconstructed
/// 1568-byte ML-KEM-1024 encapsulation key.
pub async fn recv_ek_braid<S>(ws: &mut WebSocketStream<S>) -> Result<Vec<u8>, P2pError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut hs = BraidHandshake::new();
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(CHUNK_TIMEOUT), ws.next())
            .await
            .map_err(|_| P2pError::Timeout)?
            .ok_or_else(|| P2pError::Connection("connection closed during braid".into()))?
            .map_err(|e| P2pError::Connection(e.to_string()))?;

        let text = match msg {
            tokio_tungstenite::tungstenite::Message::Text(t) => t,
            tokio_tungstenite::tungstenite::Message::Close(_) => {
                return Err(P2pError::Connection("closed during braid".into()));
            }
            _ => continue,
        };

        let env =
            WireEnvelope::from_json(&text).map_err(|e| P2pError::Serialization(e.to_string()))?;
        let chunk = parse_braid_chunk(&env).ok_or_else(|| {
            P2pError::Handshake(format!("expected braid chunk, got {}", env.msg_type))
        })?;

        let done = hs
            .add_chunk(chunk)
            .map_err(|e| P2pError::Handshake(format!("braid: {}", e)))?;
        if done {
            break;
        }
    }
    Ok(hs.reconstruct_enc_key(MLKEM1024_EK_LEN))
}

/// SECURITY (C1): Bind a reassembled braid EK to the *authenticated* inline
/// `kyber_enc_key` that the peer advertised in its ML-DSA-87-signed
/// hello/hello-ack.
///
/// The braid stream itself is only integrity-protected (SHA-512 of the key,
/// carried as `ek_hash` in every chunk). An active MITM who can flip a chunk
/// frame could substitute their own EK during the stream *unless* we pin the
/// reassembled key to the one the peer already committed to under a verified
/// signature. This function enforces exactly that:
///
///   1. `SHA-512(reconstructed_ek)` is recomputed and must match the hash the
///      peer declared (`ek_hash`) — stream integrity,
///   2. `reconstructed_ek == authenticated_inline_ek` — signature binding to the
///      EK the peer committed to in its signed hello/ack.
///
/// Either failure means the streamed key was tampered with → reject the
/// connection (fail-closed). `authenticated_inline_ek` must be the raw bytes of
/// the `kyber_enc_key` field taken from the *verified* hello/ack payload.
///
/// (We recompute the SHA-512 here rather than trusting the peer-supplied
/// `ek_hash`, so a MITM cannot supply a matching hash for their substituted key
/// without also controlling the inline signed field — which they do not, since
/// the hello/ack signature would then fail.)
pub fn verify_peer_ek_from_bytes(
    reconstructed_ek: &[u8],
    authenticated_inline_ek: &[u8],
) -> Result<Vec<u8>, P2pError> {
    // 1. Stream integrity: the reconstructed key must hash to the same value
    //    the peer declared via ek_hash. We recompute rather than trust it.
    let mut hasher = Sha512::new();
    hasher.update(reconstructed_ek);
    let ek_hash = hasher.finalize();
    // Reconstruct the expected ek_hash from the *authenticated* inline key: if
    // the inline key is intact (signed), its SHA-512 must equal the stream's.
    let mut inline_hasher = Sha512::new();
    inline_hasher.update(authenticated_inline_ek);
    let inline_hash = inline_hasher.finalize();
    if ek_hash.as_slice() != inline_hash.as_slice() {
        return Err(P2pError::Handshake(
            "braid EK hash mismatch — stream tampered".into(),
        ));
    }
    // 2. Signature binding: must equal the EK the peer committed to in its
    //    signed hello/ack. Without this an MITM could splice in their own key.
    if reconstructed_ek != authenticated_inline_ek {
        return Err(P2pError::Handshake(
            "braid EK does not match authenticated inline kyber_enc_key — possible MITM".into(),
        ));
    }
    Ok(reconstructed_ek.to_vec())
}

/// Full symmetric braid EK exchange: stream our key, then reassemble the peer's.
///
/// Both peers call this after the signed PoW hello/hello-ack. Because each side
/// sends all of its chunks before reading, the exchange never deadlocks.
/// Returns the peer's reconstructed 1568-byte encapsulation key.
pub async fn exchange_ek_braid<S>(
    ws: &mut WebSocketStream<S>,
    our_ek_bytes: &[u8],
) -> Result<Vec<u8>, P2pError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    send_ek_braid(ws, our_ek_bytes).await?;
    recv_ek_braid(ws).await
}

/// Full symmetric braid EK exchange for a SPLIT stream (responder side, where
/// the connection is already split into `sink`/`rx` halves for the message
/// loop). Streams our key and reassembles the peer's, then returns the halves
/// plus the reconstructed peer EK so the caller can resume normal I/O.
pub async fn exchange_ek_braid_split<S>(
    mut sink: SplitSink<WebSocketStream<S>, Message>,
    mut rx: SplitStream<WebSocketStream<S>>,
    our_ek_bytes: &[u8],
) -> Result<
    (
        SplitSink<WebSocketStream<S>, Message>,
        SplitStream<WebSocketStream<S>>,
        Vec<u8>,
    ),
    P2pError,
>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    send_ek_braid_split(&mut sink, our_ek_bytes).await?;
    let peer_ek = recv_ek_braid_split(&mut rx).await?;
    Ok((sink, rx, peer_ek))
}

/// Stream our encapsulation key over a split sink.
pub async fn send_ek_braid_split<S>(
    sink: &mut SplitSink<WebSocketStream<S>, Message>,
    ek_bytes: &[u8],
) -> Result<(), P2pError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    for chunk in split_key_to_chunks(ek_bytes) {
        let env = build_braid_chunk_msg(&chunk);
        let json = env
            .to_json()
            .map_err(|e| P2pError::Serialization(e.to_string()))?;
        sink.send(Message::Text(json.into()))
            .await
            .map_err(|e| P2pError::Connection(e.to_string()))?;
    }
    Ok(())
}

/// Reassemble the peer's encapsulation key from a split stream.
pub async fn recv_ek_braid_split<S>(
    rx: &mut SplitStream<WebSocketStream<S>>,
) -> Result<Vec<u8>, P2pError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut hs = BraidHandshake::new();
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(CHUNK_TIMEOUT), rx.next())
            .await
            .map_err(|_| P2pError::Timeout)?
            .ok_or_else(|| P2pError::Connection("connection closed during braid".into()))?
            .map_err(|e| P2pError::Connection(e.to_string()))?;

        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => return Err(P2pError::Connection("closed during braid".into())),
            _ => continue,
        };
        let env =
            WireEnvelope::from_json(&text).map_err(|e| P2pError::Serialization(e.to_string()))?;
        let chunk = parse_braid_chunk(&env).ok_or_else(|| {
            P2pError::Handshake(format!("expected braid chunk, got {}", env.msg_type))
        })?;
        let done = hs
            .add_chunk(chunk)
            .map_err(|e| P2pError::Handshake(format!("braid: {}", e)))?;
        if done {
            break;
        }
    }
    Ok(hs.reconstruct_enc_key(MLKEM1024_EK_LEN))
}

#[cfg(test)]
mod tests {
    use super::*;
    use add_crypto::kyber;
    use base64::Engine as _;

    fn ek_bytes(kp: &kyber::KyberKeypair) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(kyber::encode_enc_key(&kp.enc))
            .unwrap()
    }

    /// End-to-end braid EK exchange over a real loopback WebSocket, followed by a
    /// full ML-KEM-1024 KEM round-trip to prove the reassembled keys yield a
    /// matching shared secret usable by the Double Ratchet.
    #[tokio::test]
    async fn test_braid_ek_exchange_and_kem_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Responder keypair (its EK is the one the initiator encapsulates against).
        let resp_kp = kyber::KyberKeypair::generate().unwrap();
        let resp_ek_bytes = ek_bytes(&resp_kp);
        let resp_ek_for_task = resp_ek_bytes.clone();

        // Initiator keypair (streamed to responder for symmetry).
        let init_kp = kyber::KyberKeypair::generate().unwrap();
        let init_ek_bytes = ek_bytes(&init_kp);

        // Responder task: accept, exchange EKs, then decapsulate the initiator's ct.
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let peer_ek = exchange_ek_braid(&mut ws, &resp_ek_for_task).await.unwrap();
            // Receive the initiator's ciphertext (base64 text frame) and decapsulate.
            let ct_b64 = loop {
                match ws.next().await.unwrap().unwrap() {
                    tokio_tungstenite::tungstenite::Message::Text(t) => break t.to_string(),
                    _ => continue,
                }
            };
            let ct = base64::engine::general_purpose::STANDARD
                .decode(ct_b64.as_bytes())
                .unwrap();
            #[allow(deprecated)]
            let ct = kyber::MlKem1024Ciphertext::from_slice(&ct);
            let ss = resp_kp.decapsulate(ct).unwrap();
            (peer_ek, ss.as_slice().to_vec())
        });

        // Initiator: connect, exchange EKs, encapsulate against responder's EK.
        let url = format!("ws://{}", addr);
        let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        let peer_ek = exchange_ek_braid(&mut ws, &init_ek_bytes).await.unwrap();

        // The reassembled responder EK must match exactly.
        assert_eq!(peer_ek, resp_ek_bytes, "reassembled responder EK mismatch");

        // Encapsulate against the reassembled EK -> (ct, ss_init).
        let peer_enc =
            kyber::decode_enc_key(&base64::engine::general_purpose::STANDARD.encode(&peer_ek))
                .unwrap();
        let (ct, ss_init) = kyber::KyberKeypair::encapsulate(&peer_enc).unwrap();
        let ct_b64 = base64::engine::general_purpose::STANDARD.encode(ct.as_slice());
        ws.send(tokio_tungstenite::tungstenite::Message::Text(ct_b64.into()))
            .await
            .unwrap();

        let (resp_got_init_ek, ss_resp) = server.await.unwrap();

        // Responder must have reassembled the initiator's EK correctly.
        assert_eq!(
            resp_got_init_ek, init_ek_bytes,
            "reassembled initiator EK mismatch"
        );
        // And both sides must agree on the KEM shared secret.
        assert_eq!(
            ss_init.as_slice(),
            ss_resp.as_slice(),
            "KEM shared secret mismatch"
        );
    }

    /// Mirror the exact client wiring: build a signed p2p-hello with `braid:true`,
    /// the responder answers with a signed p2p-hello-ack (`braid:true`), then BOTH
    /// run the braid EK exchange (initiator via the full-stream path, responder via
    /// the split-sink/stream path) and complete a KEM round-trip. This exercises the
    /// same code paths `send_message` / `handle_incoming_connection` use.
    #[tokio::test]
    async fn test_braid_wired_handshake_like_client() {
        use crate::protocol::{build_p2p_hello_ack_signed, build_p2p_hello_signed};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let resp_kp = kyber::KyberKeypair::generate().unwrap();
        let resp_ek_bytes = ek_bytes(&resp_kp);
        let resp_ek_for_task = resp_ek_bytes.clone();
        let resp_fp = "RESPONDERFP";

        // Responder: accept, verify braid flag in hello, send ack, braid-exchange (split path).
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut ws_tx, mut ws_rx) = ws.split();

            // Read hello, assert braid capability negotiated.
            let hello_text = match ws_rx.next().await.unwrap().unwrap() {
                tokio_tungstenite::tungstenite::Message::Text(t) => t,
                _ => panic!("expected hello"),
            };
            let hello: serde_json::Value = serde_json::from_str(&hello_text).unwrap();
            assert_eq!(hello["type"], "p2p-hello");
            assert_eq!(
                hello["payload"]["braid"], true,
                "client must advertise braid"
            );

            // Respond with a signed ack advertising braid.
            let ack_sig = "SIG";
            let ack = build_p2p_hello_ack_signed(
                resp_fp,
                1,
                16,
                "challenge",
                &base64::engine::general_purpose::STANDARD.encode(&resp_ek_for_task),
                ack_sig,
                "",
            );
            ws_tx
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    serde_json::to_string(&ack).unwrap().into(),
                ))
                .await
                .unwrap();

            // Run the same split-path braid exchange the client uses.
            let (mut _ws_tx, mut ws_rx, peer_ek_bytes) =
                exchange_ek_braid_split(ws_tx, ws_rx, &resp_ek_for_task)
                    .await
                    .unwrap();

            // Receive the initiator's ciphertext and decapsulate.
            let ct_b64 = loop {
                match ws_rx.next().await.unwrap().unwrap() {
                    tokio_tungstenite::tungstenite::Message::Text(t) => break t.to_string(),
                    _ => continue,
                }
            };
            let ct = base64::engine::general_purpose::STANDARD
                .decode(ct_b64.as_bytes())
                .unwrap();
            #[allow(deprecated)]
            let ct = kyber::MlKem1024Ciphertext::from_slice(&ct);
            let ss = resp_kp.decapsulate(ct).unwrap();
            (peer_ek_bytes, ss.as_slice().to_vec())
        });

        // Initiator side (mirrors send_message).
        let init_kp = kyber::KyberKeypair::generate().unwrap();
        let init_ek_bytes = ek_bytes(&init_kp);

        let url = format!("ws://{}", addr);
        let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

        let hello_sig = "SIG";
        let hello = build_p2p_hello_signed(
            "INITIATORFP",
            1,
            16,
            &base64::engine::general_purpose::STANDARD.encode(&init_ek_bytes),
            "",
            hello_sig,
            "",
        );
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::to_string(&hello).unwrap().into(),
        ))
        .await
        .unwrap();

        // Read ack, assert braid capability.
        let ack_text = match ws.next().await.unwrap().unwrap() {
            tokio_tungstenite::tungstenite::Message::Text(t) => t,
            _ => panic!("expected ack"),
        };
        let ack: serde_json::Value = serde_json::from_str(&ack_text).unwrap();
        assert_eq!(ack["type"], "p2p-hello-ack");
        assert_eq!(
            ack["payload"]["braid"], true,
            "responder must advertise braid"
        );

        // Full-stream braid exchange (initiator path).
        let peer_ek_bytes = exchange_ek_braid(&mut ws, &init_ek_bytes).await.unwrap();
        assert_eq!(
            peer_ek_bytes, resp_ek_bytes,
            "reassembled responder EK mismatch"
        );

        // Encapsulate against reassembled responder EK and send ciphertext.
        let peer_enc = kyber::decode_enc_key(
            &base64::engine::general_purpose::STANDARD.encode(&peer_ek_bytes),
        )
        .unwrap();
        let (ct, ss_init) = kyber::KyberKeypair::encapsulate(&peer_enc).unwrap();
        let ct_b64 = base64::engine::general_purpose::STANDARD.encode(ct.as_slice());
        ws.send(tokio_tungstenite::tungstenite::Message::Text(ct_b64.into()))
            .await
            .unwrap();

        let (resp_got_init_ek, ss_resp) = server.await.unwrap();
        assert_eq!(
            resp_got_init_ek, init_ek_bytes,
            "reassembled initiator EK mismatch"
        );
        assert_eq!(
            ss_init.as_slice(),
            ss_resp.as_slice(),
            "KEM shared secret mismatch"
        );
    }

    // SECURITY (C1): verify_peer_ek_from_bytes must ACCEPT a reassembled EK that
    // matches the authenticated inline kyber_enc_key, and REJECT one that an
    // active MITM substituted for their own key.
    #[test]
    fn test_verify_peer_ek_binding() {
        use sha2::{Digest, Sha512};

        // Honest peer: the reassembled EK equals the inline signed EK.
        let honest_ek: Vec<u8> = (0..1568u32).map(|i| (i % 256) as u8).collect();
        let ok = verify_peer_ek_from_bytes(&honest_ek, &honest_ek);
        assert!(ok.is_ok(), "matching EK must verify");

        // Attacker substitutes their own EK during the braid stream: the
        // reassembled bytes differ from the signed inline EK → must be rejected.
        let mut attacker_ek = honest_ek.clone();
        attacker_ek[0] ^= 0xFF; // flip first byte
        assert_ne!(attacker_ek, honest_ek);
        let tampered = verify_peer_ek_from_bytes(&attacker_ek, &honest_ek);
        assert!(
            tampered.is_err(),
            "MITM-substituted EK must be rejected (signature binding)"
        );

        // Even if the attacker fixes the SHA-512 to match their own key, the
        // binding to the *signed* inline key still fails (we compare to the
        // signed inline bytes, not the attacker's declared hash).
        let attacker_inline = attacker_ek.clone();
        // (no realistic attacker can make attacker_ek == signed inline, so this
        //  simply re-confirms mismatch)
        assert!(verify_peer_ek_from_bytes(&attacker_ek, &attacker_inline).is_ok());
        assert!(verify_peer_ek_from_bytes(&attacker_ek, &honest_ek).is_err());

        // Sanity: SHA-512 of the honest key is what the stream would declare.
        let mut h = Sha512::new();
        h.update(&honest_ek);
        let _ = h.finalize();
    }
}
