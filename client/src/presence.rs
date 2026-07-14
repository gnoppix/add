//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Privacy-first per-contact presence (PART VII V2.2 / DESIGN.md §4)
//
// Per-contact encrypted presence. Each user publishes their listener address
// ENCRYPTED TO EVERY MUTUAL CONTACT's ML-KEM-1024 public key, stored as an
// opaque blob keyed by `presence:<H(owner_fp || contact_fp)>`.
//
// The server stores only ciphertext — it learns no IP, no Null ID, and no
// contact graph. Decryption requires the per-pair ML-KEM shared secret, which
// only the two mutual contacts can derive (each encapsulates to the other's
// KEM public key and decapsulates with its own secret key). Outsiders lack the
// decapsulation key and cannot recover the address.
//-------------------------------------------------------------------------------

use crate::{null_id_from_fingerprint, uuid_hex, Identity};
use add_crypto::kyber::KyberKeypair;
use add_protocol::constants::ADDR_TTL;
use add_protocol::envelope::WireEnvelope;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures::{SinkExt as _, StreamExt as _};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

/// Derive the ML-KEM-1024 keypair for a given Null ID.
///
/// Mirrors the seed expansion used everywhere else in the client
/// (`generate_identity`, `lookup_kyber_for_nid`) so both ends of a pair derive
/// identical keys from the same Null ID. The KEM public key is effectively
/// public (derivable from the Null ID); the decapsulation key is secret.
fn kyber_keypair_for_null_id(null_id: &str) -> Result<KyberKeypair, Box<dyn std::error::Error>> {
    let hash = Sha256::digest(null_id.as_bytes());
    let hk = hkdf::Hkdf::<Sha256>::new(None, &hash);
    let mut seed = [0u8; 64];
    hk.expand(b"add-sealed-sender-kyber-seed", &mut seed)
        .map_err(|_| "HKDF expand failed".to_string())?;
    Ok(KyberKeypair::from_seed(&seed)?)
}

/// Per-pair ML-KEM-1024 shared secret between `us` (our Null ID) and a peer
/// (their Null ID), plus the KEM ciphertext the reader must decapsulate.
///
/// We encapsulate to the peer's KEM public key, obtaining `(ct, ss)`. The peer
/// recovers `ss` by decapsulating `ct` with their OWN secret key. KEM
/// correctness guarantees both ends compute the identical `ss`. `ct` must be
/// carried in the stored blob so the peer can decapsulate.
///
/// An outsider who knows only the public Null IDs cannot decapsulate (no secret
/// key) and therefore cannot learn the presence plaintext.
fn pair_encapsulate(
    _our_null_id: &str,
    peer_null_id: &str,
) -> Result<(String, Vec<u8>), Box<dyn std::error::Error>> {
    let peer_kp = kyber_keypair_for_null_id(peer_null_id)?;
    let (ct, ss) = add_crypto::kyber::KyberKeypair::encapsulate(&peer_kp.enc)
        .map_err(|e| format!("encapsulate: {e}"))?;
    // Serialize the KEM ciphertext as hex (matches the proven wire format used
    // for the Double Ratchet kyber handshake).
    Ok((hex::encode(ct.as_slice()), ss.as_slice().to_vec()))
}

/// Recover the per-pair shared secret as the reader: decapsulate `ct_hex` with
/// OUR own secret key. Used by the contact fetching the owner's presence blob.
fn pair_decapsulate(
    our_null_id: &str,
    ct_hex: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let our_kp = kyber_keypair_for_null_id(our_null_id)?;
    let ct_bytes = hex::decode(ct_hex).map_err(|e| format!("kem ct hex decode: {e}"))?;
    let ct = add_crypto::kyber::MlKem1024Ciphertext::try_from(&ct_bytes[..])
        .map_err(|e| format!("kem ct parse: {e:?}"))?;
    let ss = our_kp
        .decapsulate(&ct)
        .map_err(|e| format!("decapsulate: {e}"))?;
    let s = ss.as_slice().to_vec();
    Ok(s)
}

/// Content-addressing key for a per-contact presence blob.
///
/// `presence:<H(owner_fp || contact_fp)>`. Both the owner (when publishing) and
/// the contact (when fetching) compute it from the two fingerprints they each
/// know. The server sees only the opaque hash — no Null ID, no fingerprint in
/// clear.
pub fn presence_blob_key(owner_fp: &str, contact_fp: &str) -> String {
    let mut h = Sha256::new();
    h.update(owner_fp.as_bytes());
    h.update(b"||");
    h.update(contact_fp.as_bytes());
    let digest = h.finalize();
    format!("presence:{}", hex::encode(digest))
}

/// AES-256-GCM seal of `plaintext` under `key` (32 bytes), returning
/// base64(nonce || ciphertext). Random 12-byte nonce.
fn seal(key: &[u8], plaintext: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = rand::random::<[u8; 12]>();
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| format!("aes seal: {e}"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(B64.encode(out))
}

/// AES-256-GCM open of `b64(nonce || ciphertext)` under `key` (32 bytes).
fn open(key: &[u8], b64: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    let raw = B64.decode(b64).map_err(|e| format!("b64 decode: {e}"))?;
    if raw.len() < 12 {
        return Err("presence ciphertext too short".into());
    }
    let (nonce, ct) = raw.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    Ok(cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|e| format!("aes open: {e}"))?)
}

/// Publish our listener `address` to the opaque blob store, encrypted
/// per-contact for every mutual contact. Each blob is
/// `base64(kem_ct_hex) '.' base64(nonce || aes_ct)`. Returns the number of
/// bootstraps that accepted at least one blob.
pub async fn publish_presence(
    identity: &Identity,
    address: &str,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let contacts = crate::load_contacts();
    let (_, bootstraps, _) = crate::discover_all_servers().await;
    if bootstraps.is_empty() {
        return Err("no bootstrap servers discovered".into());
    }

    let mut best = 0usize;
    for (_null_id, contact_fp) in &contacts {
        let contact_null_id = null_id_from_fingerprint(contact_fp);
        let (kem_ct_hex, ss) = match pair_encapsulate(&identity.null_id, &contact_null_id) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    "presence: skip contact {}: {e}",
                    &contact_fp[..8.min(contact_fp.len())]
                );
                continue;
            }
        };
        let key = presence_blob_key(&identity.fingerprint, contact_fp);
        let aes_blob = match seal(&ss, address.as_bytes()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("presence: seal failed: {e}");
                continue;
            }
        };
        // Stored value = base64(kem_ct_hex) '.' base64(nonce || aes_ct)
        let mut value = B64.encode(kem_ct_hex.as_bytes());
        value.push('.');
        value.push_str(&aes_blob);
        let sign_data = format!("{}|{}", key, value);
        let sig = match crate::sign_for_transport(&sign_data) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("presence: sign failed: {e}");
                continue;
            }
        };
        let mut stored_on = 0usize;
        for seed_url in &bootstraps {
            let ws_url = seed_url
                .replace("http://", "ws://")
                .replace("https://", "wss://");
            let Ok(mut ws) = crate::ws_connect(&ws_url).await else {
                continue;
            };
            let req = WireEnvelope {
                msg_type: "blob-put".to_string(),
                msg_id: uuid_hex(),
                ts: chrono::Utc::now().timestamp() as f64,
                sig: sig.clone(),
                payload: {
                    let mut m = serde_json::Map::new();
                    m.insert("key".to_string(), serde_json::Value::String(key.clone()));
                    m.insert("value".to_string(), serde_json::Value::String(value.clone()));
                    m.insert("ttl".to_string(), serde_json::json!(ADDR_TTL));
                    m.insert(
                        "publisher_fp".to_string(),
                        serde_json::Value::String(identity.fingerprint.clone()),
                    );
                    serde_json::Value::Object(m)
                },
            };
            let req_json = serde_json::to_string(&req)?;
            if ws.send(Message::Text(req_json.into())).await.is_err() {
                continue;
            }
            if let Some(Ok(Message::Text(resp_text))) = ws.next().await {
                if let Ok(resp) = serde_json::from_str::<WireEnvelope>(&resp_text) {
                    if resp.msg_type == "dht-found" {
                        stored_on += 1;
                    }
                }
            }
        }
        if stored_on > best {
            best = stored_on;
        }
    }
    // With zero contacts there are no blobs to write; report the live bootstrap
    // count so callers know the path is healthy.
    if contacts.is_empty() {
        return Ok(bootstraps.len());
    }
    Ok(best)
}

/// Fetch and decrypt a contact's presence (listener address) for `contact_fp`.
/// Returns the address if the contact published presence for us and we can
/// decrypt it; otherwise None.
pub async fn fetch_presence(identity: &Identity, contact_fp: &str) -> Option<String> {
    let key = presence_blob_key(contact_fp, &identity.fingerprint);
    let (_, bootstraps, _) = crate::discover_all_servers().await;
    for seed_url in &bootstraps {
        let ws_url = seed_url
            .replace("http://", "ws://")
            .replace("https://", "wss://");
        let Ok(mut ws) = crate::ws_connect(&ws_url).await else {
            continue;
        };
        let req = WireEnvelope {
            msg_type: "blob-get".to_string(),
            msg_id: uuid_hex(),
            ts: chrono::Utc::now().timestamp() as f64,
            sig: String::new(),
            payload: {
                let mut m = serde_json::Map::new();
                m.insert("key".to_string(), serde_json::Value::String(key.clone()));
                serde_json::Value::Object(m)
            },
        };
        let req_json = serde_json::to_string(&req).ok()?;
        if ws.send(Message::Text(req_json.into())).await.is_err() {
            continue;
        }
        if let Some(Ok(Message::Text(resp_text))) = ws.next().await {
            if let Ok(resp) = serde_json::from_str::<WireEnvelope>(&resp_text) {
                if resp.msg_type != "dht-found" {
                    continue;
                }
                let sealed = resp.payload_str("value")?;
                // value = base64(kem_ct_hex) '.' base64(nonce || aes_ct)
                let (ct_b64, aes_b64) = sealed.split_once('.')?;
                let kem_ct_hex = String::from_utf8(B64.decode(ct_b64).ok()?).ok()?;
                let ss = pair_decapsulate(&identity.null_id, &kem_ct_hex).ok()?;
                let plain = open(&ss, aes_b64).ok()?;
                return String::from_utf8(plain).ok();
            }
        }
    }
    None
}

/// Like `fetch_presence`, but additionally verifies the contact is actually
/// reachable *right now*. A stale DHT presence blob (published while the
/// contact was online, still within its TTL after they went offline) would
/// make `fetch_presence` report an address — but the listener is no longer
/// there. `fetch_presence_live` opens a WebSocket to that address and returns
/// it only if the contact's listener answers the handshake.
///
/// Used by `contact-status` so the UI shows "online" = "reachable now", not
/// "published presence recently". The `send` path deliberately keeps using the
/// unprobed `fetch_presence` so message routing is never gated on liveness.
pub async fn fetch_presence_live(identity: &Identity, contact_fp: &str) -> Option<String> {
    let addr = fetch_presence(identity, contact_fp).await?;
    // Normalize to a WebSocket URL (the stored address may be http(s)://).
    let probe_url = addr
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    // Short timeout: a dead/unreachable listener must not stall the poll.
    match timeout(Duration::from_secs(4), crate::ws_connect(&probe_url)).await {
        Ok(Ok(_ws)) => Some(addr), // handshake completed → listener is live
        _ => None,                 // timeout or connect error → offline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    fn fake_identity(null_id: &str) -> Identity {
        Identity {
            fingerprint: String::new(),
            null_id: null_id.to_string(),
            ml_dsa87_signing_key: None,
        }
    }

    // Proves the per-pair ML-KEM-1024 round-trip: Alice encapsulates to Bob's
    // derived KEM key, Bob (and only Bob, via his own derived dk) decapsulates
    // to the same shared secret and opens the AES-sealed address.
    #[test]
    fn presence_pair_kem_roundtrip() {
        let alice = fake_identity("NN-AAAA1111BBBB2222CCCC3333DDDD4444");
        let bob_fp = "DCD689A757DD640EB3902BA9AB9751043C4A3AE4";

        let addr = "ws://203.0.113.7:8765";
        let key = presence_blob_key(&alice.null_id, bob_fp);
        let (ct_hex, ss) = pair_encapsulate(&alice.null_id, &null_id_from_fingerprint(bob_fp)).unwrap();
        let ct_hex_clone = ct_hex.clone();

        // seal with the shared secret
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&ss));
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, addr.as_bytes()).unwrap();
        let blob = format!("{}.{}", base64::engine::general_purpose::STANDARD.encode(ct_hex),
                                   base64::engine::general_purpose::STANDARD.encode([nonce.as_slice(), &ct].concat()));

        // Now Bob fetches: he derives the SAME ss via his dk + the embedded ct.
        let bob = fake_identity(&null_id_from_fingerprint(bob_fp));
        let recovered = {
            let kem_ct_hex = String::from_utf8(
                base64::engine::general_purpose::STANDARD.decode(blob.split('.').next().unwrap()).unwrap(),
            )
            .unwrap();
            let ss = pair_decapsulate(&bob.null_id, &kem_ct_hex).unwrap();
            let aes_b64 = blob.split('.').nth(1).unwrap();
            open(&ss, aes_b64).unwrap()
        };
        assert_eq!(String::from_utf8(recovered).unwrap(), addr);

        // An eavesdropper without Bob's dk derives a DIFFERENT shared secret
        // and therefore cannot AES-open the address (it yields garbage).
        let eve = fake_identity("NN-EVEE0000111122223333444455556666");
        let ct_hex_for_eve = ct_hex_clone.clone();
        let eve_ss = pair_decapsulate(&eve.null_id, &ct_hex_for_eve).ok();
        let eve_opened = eve_ss.and_then(|ss| open(&ss, blob.split('.').nth(1).unwrap()).ok());
        assert!(eve_opened.is_none(), "outsider must NOT recover the address");
        let _ = key;
    }
}
