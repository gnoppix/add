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

use crate::{Identity, null_id_from_fingerprint, uuid_hex};
use crate::{load_or_generate_kyber, DbEncryptionKey};
use add_crypto::kyber::KyberKeypair;
use add_protocol::constants::ADDR_TTL;
use add_protocol::envelope::WireEnvelope;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use futures::{SinkExt as _, StreamExt as _};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

/// SECURITY (F-1): The per-contact KEM keypair is NO LONGER derived from the
/// public Null ID. Each user generates ONE random ML-KEM-1024 keypair at
/// identity creation (see `load_or_generate_kyber`) and publishes its
/// *encapsulation* (public) key inside the cert bundle. Presence blobs are
/// sealed to the contact's PUBLISHED KEM public key, and opened with our own
/// random secret key. An outsider who only knows the public Null ID / cert
/// cannot reconstruct the decapsulation key, so presence IPs stay secret.

/// Per-pair ML-KEM-1024 shared secret between us and a peer, plus the KEM
/// ciphertext the reader must decapsulate.
///
/// We encapsulate to the peer's PUBLISHED KEM public key (fetched from the
/// opaque cert store), obtaining `(ct, ss)`. The peer recovers `ss` by
/// decapsulating `ct` with their OWN random secret key. An outsider who only
/// knows the public Null ID cannot derive the peer's secret key and therefore
/// cannot learn the presence plaintext.
async fn pair_encapsulate(
    peer_fp: &str,
) -> Result<(String, Vec<u8>), Box<dyn std::error::Error>> {
    let (_, bootstraps, _) = crate::discover_all_servers().await;
    let mut last_err = String::new();
    for seed_url in &bootstraps {
        match crate::dht_fetch_cert(seed_url, peer_fp).await {
            Ok((_, _, kyber_enc_b64)) if !kyber_enc_b64.is_empty() => {
                let peer_enc = match add_crypto::kyber::decode_enc_key(&kyber_enc_b64) {
                    Ok(k) => k,
                    Err(e) => {
                        last_err = format!("peer kem decode: {e}");
                        continue;
                    }
                };
                let (ct, ss) = add_crypto::kyber::KyberKeypair::encapsulate(&peer_enc)
                    .map_err(|e| format!("encapsulate: {e}"))?;
                return Ok((hex::encode(ct), ss.as_slice().to_vec()));
            }
            Ok(_) => {
                last_err = "peer cert has no kem enc key".into();
            }
            Err(e) => {
                last_err = format!("cert fetch: {e}");
            }
        }
    }
    Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("pair_encapsulate: {last_err}"))))
}

/// Recover the per-pair shared secret as the reader: decapsulate `ct_hex` with
/// OUR OWN random secret key (loaded from disk).
fn pair_decapsulate(
    our_kp: &KyberKeypair,
    ct_hex: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let ct_bytes = hex::decode(ct_hex).map_err(|e| format!("kem ct hex decode: {e}"))?;
    let ct = add_crypto::kyber::MlKem1024Ciphertext::try_from(&ct_bytes[..])
        .map_err(|e| format!("kem ct parse: {e:?}"))?;
    let ss = our_kp
        .decapsulate(&ct)
        .map_err(|e| format!("decapsulate: {e}"))?;
    Ok(ss.as_slice().to_vec())
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
    for contact_fp in contacts.values() {
        let (kem_ct_hex, ss) = match pair_encapsulate(contact_fp).await {
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
                    m.insert(
                        "value".to_string(),
                        serde_json::Value::String(value.clone()),
                    );
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
            if let Some(Ok(Message::Text(resp_text))) = ws.next().await
                && let Ok(resp) = serde_json::from_str::<WireEnvelope>(&resp_text)
                && resp.msg_type == "dht-found"
            {
                stored_on += 1;
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
    // Our KEM secret key (random, on disk) — needed to decapsulate the blob.
    let db_key = DbEncryptionKey::load_or_create_sync();
    let our_kp = load_or_generate_kyber(&identity.null_id, db_key.key()).ok()?;
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
        if let Some(Ok(Message::Text(resp_text))) = ws.next().await
            && let Ok(resp) = serde_json::from_str::<WireEnvelope>(&resp_text)
            && resp.msg_type == "dht-found"
        {
            let sealed = resp.payload_str("value")?;
            // value = base64(kem_ct_hex) '.' base64(nonce || aes_ct)
            let (ct_b64, aes_b64) = sealed.split_once('.')?;
            let kem_ct_hex = String::from_utf8(B64.decode(ct_b64).ok()?).ok()?;
            let ss = pair_decapsulate(&our_kp, &kem_ct_hex).ok()?;
            let plain = open(&ss, aes_b64).ok()?;
            return String::from_utf8(plain).ok();
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

    // Proves the per-pair ML-KEM-1024 round-trip: Alice generates a random
    // keypair, encapsulates to Bob's REAL public key (published in his cert in
    // production), Bob decapsulates with his own secret key to the same shared
    // secret and opens the AES-sealed address.
    #[test]
    fn presence_pair_kem_roundtrip() {
        let alice = fake_identity("NN-AAAA1111BBBB2222CCCC3333DDDD4444");
        let bob_fp = "DCD689A757DD640EB3902BA9AB9751043C4A3AE4";

        let addr = "ws://203.0.113.7:8765";
        let key = presence_blob_key(&alice.null_id, bob_fp);

        // Bob's REAL random KEM keypair (in production loaded from disk / cert).
        let bob_kp = add_crypto::kyber::KyberKeypair::generate().unwrap();
        let bob_pub = bob_kp.enc.clone();
        let ct_hex = {
            let (ct, ss) = add_crypto::kyber::KyberKeypair::encapsulate(&bob_pub).unwrap();
            // split_once needs (hex(ct) of the FULL wire ciphertext, ss)
            (hex::encode(&ct), ss)
        };
        let (ct_hex, ss) = ct_hex;
        let ct_hex_clone = ct_hex.clone();

        // seal with the shared secret
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&ss));
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, addr.as_bytes()).unwrap();
        let blob = format!(
            "{}.{}",
            base64::engine::general_purpose::STANDARD.encode(ct_hex),
            base64::engine::general_purpose::STANDARD.encode([nonce.as_slice(), &ct].concat())
        );

        // Now Bob fetches: he decapsulates the embedded ct with his secret key.
        let bob = fake_identity(&null_id_from_fingerprint(bob_fp));
        let recovered = {
            let kem_ct_hex = String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(blob.split('.').next().unwrap())
                    .unwrap(),
            )
            .unwrap();
            let ct_bytes = hex::decode(&kem_ct_hex).unwrap();
            let kyber_ct = add_crypto::kyber::MlKem1024Ciphertext::try_from(&ct_bytes[..]).unwrap();
            let ss = bob_kp.decapsulate(&kyber_ct).unwrap();
            let aes_b64 = blob.split('.').nth(1).unwrap();
            open(&ss, aes_b64).unwrap()
        };
        assert_eq!(String::from_utf8(recovered).unwrap(), addr);

        // An eavesdropper without Bob's dk cannot decapsulate the KEM ciphertext
        // at all and therefore cannot AES-open the address (it yields garbage).
        let eve_kp = add_crypto::kyber::KyberKeypair::generate().unwrap();
        let eve_ct_bytes = hex::decode(&ct_hex_clone).unwrap();
        let eve_kyber_ct = add_crypto::kyber::MlKem1024Ciphertext::try_from(&eve_ct_bytes[..]).unwrap();
        let eve_ss = eve_kp.decapsulate(&eve_kyber_ct).ok();
        let eve_opened = eve_ss.and_then(|ss| open(&ss, blob.split('.').nth(1).unwrap()).ok());
        assert!(
            eve_opened.is_none(),
            "outsider must NOT recover the address"
        );
        let _ = key;
        let _ = bob;
    }
}
