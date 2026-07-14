//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
use anyhow::{Result, anyhow};
use base64::engine::Engine as _;
use base64::engine::general_purpose::STANDARD as base64_standard;
use clap::Parser;
use futures::{SinkExt as _, StreamExt as _};
use rustls::crypto::CryptoProvider;
use rustls::crypto::ring::default_provider;
use std::path::PathBuf;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

mod config;

use config::BotConfig;

#[derive(Parser, Debug)]
#[command(name = "add-reflector", version, about = "Add Reflector (Echo) Bot")]
struct Args {
    /// Path to configuration file
    #[arg(long, default_value = "~/.add/bot/bot.toml")]
    config: String,

    /// Override prefix for echoed messages
    #[arg(long)]
    prefix: Option<String>,

    /// Override TTL (seconds)
    #[arg(long)]
    ttl: Option<u64>,

    /// Run once and exit (for testing)
    #[arg(long)]
    once: bool,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Listen on specific port (0 = random)
    #[arg(long, default_value = "0")]
    port: u16,
}

fn expand_path(p: &str) -> PathBuf {
    let expanded = shellexpand::tilde(p);
    PathBuf::from(expanded.as_ref())
}

/// Best-effort discovery of the machine's primary outbound IPv4 address.
/// Used to advertise a peer-reachable P2P address (instead of 0.0.0.0).
fn primary_ipv4() -> Option<std::net::Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()? {
        std::net::SocketAddr::V4(a) => {
            let ip = a.ip();
            if ip.is_unspecified() || ip.is_loopback() {
                None
            } else {
                Some(*ip)
            }
        }
        _ => None,
    }
}

/// Default fingerprint for the reflector bot (matches contact fingerprint - GPG fingerprint)
const REFLECTOR_FINGERPRINT: &str = "3957378550B111F2678DC1B4A58C27B22091D5CF";
/// Null ID for the reflector bot (computed from fingerprint)
const REFLECTOR_NULL_ID: &str = "NN-UFtv-8fHu";

/// Seed file path for persistent reflector identity (0o600, never in git)
fn reflector_seed_path() -> PathBuf {
    std::env::var("ADD_REFLECTOR_SEED_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/add/reflector_seed"))
}

/// Load reflector signing key from seed file (persists identity across reboots)
fn load_reflector_signing_key() -> Result<(Vec<u8>, String), anyhow::Error> {
    use ml_dsa::KeyExport;

    let seed_path = reflector_seed_path();
    if seed_path.exists() {
        let seed_hex = std::fs::read_to_string(&seed_path).map_err(|e| anyhow!("seed read: {}", e))?;
        if seed_hex.trim().len() == 64 {
            let seed_bytes = hex::decode(seed_hex.trim()).map_err(|_| anyhow!("invalid hex"))?;
            let seed_arr: [u8; 32] = seed_bytes.try_into().map_err(|_| anyhow!("invalid seed length"))?;
            let kp = add_crypto_pq::MlDsa87KeyPair::from_seed(&seed_arr)?;
            let sk_seed = kp.to_seed();
            let vk_b64 = base64_standard.encode(kp.verifying_key().to_bytes());
            return Ok((sk_seed.to_vec(), vk_b64));
        }
    }

    // Generate fresh key
    let kp = add_crypto_pq::MlDsa87KeyPair::generate()?;
    let sk_seed = kp.to_seed();
    let vk_b64 = base64_standard.encode(kp.verifying_key().to_bytes());
    let seed_hex = sk_seed.iter().map(|b| format!("{:02x}", b)).collect::<String>();

    // Try to persist seed; ignore errors if directory not writable (e.g., tests)
    if let Some(parent) = seed_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::write(&seed_path, &seed_hex);
        let _ = std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::write(&seed_path, &seed_hex);
    }

    Ok((sk_seed.to_vec(), vk_b64))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Install rustls crypto provider (required since rustls 0.23)
    let _ = CryptoProvider::install_default(default_provider());

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(args.log_level.parse()?))
        .init();

    info!("Starting Add Reflector Bot v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config_path = expand_path(&args.config);
    let mut config = BotConfig::load(&config_path).await?;

    // Apply CLI overrides
    if let Some(prefix) = args.prefix {
        config.reflector.prefix = prefix;
    }
    if let Some(ttl) = args.ttl {
        config.reflector.default_ttl = Some(ttl.to_string());
    }

    info!("Bot configuration loaded:");
    info!("  Prefix: {}", config.reflector.prefix);
    info!("  Default TTL: {:?}", config.reflector.default_ttl);
    info!("  Bootstrap: {}", config.network.bootstrap_url);

    // Start P2P listener
    let listen_addr = format!("0.0.0.0:{}", args.port);
    let listener = tokio::net::TcpListener::bind(&listen_addr)
        .await
        .map_err(|e| anyhow!("Failed to bind listener on {}: {}", listen_addr, e))?;
    let local_addr = listener.local_addr()?;

    // Advertise a connectable address: the primary non-loopback IPv4 if available,
    // falling back to the bound address. 0.0.0.0 is not reachable by peers.
    let advertise_ip = std::net::IpAddr::V4(
        local_addr
            .ip()
            .is_unspecified()
            .then(primary_ipv4)
            .flatten()
            .unwrap_or_else(|| match local_addr.ip() {
                std::net::IpAddr::V4(v4) => v4,
                std::net::IpAddr::V6(v6) => {
                    v6.to_ipv4_mapped().unwrap_or(std::net::Ipv4Addr::LOCALHOST)
                }
            }),
    );
    let listen_address = format!("ws://{}:{}", advertise_ip, local_addr.port());

    info!("P2P listener on {}", listen_address);

    // Publish the reflector's public service bundle (cert + address) to the
    // opaque cert store on all bootstrap servers. This replaces the retired
    // plaintext `addr:` record — the server stores only an opaque blob, never
    // a plaintext IP↔ID mapping.
    let bootstrap_urls = vec![
        "wss://bootstrap-eu.gnoppix.org/ws".to_string(),
        "wss://bootstrap-asia.gnoppix.org/ws".to_string(),
        "wss://bootstrap-us.gnoppix.org/ws".to_string(),
    ];

    for url in &bootstrap_urls {
        if let Err(e) = publish_service_bundle(url, &listen_address).await {
            warn!("Failed to publish service bundle to {}: {}", url, e);
        } else {
            info!("Published service bundle on {}", url);
        }
    }
    info!("Published public service bundle for direct P2P discovery");

    if args.once {
        info!("Single cycle complete - exiting");
        return Ok(());
    }

    // Periodic self-heal: re-register our addr-record so that after a
    // restart (new listen port) the DHT entry is refreshed before the old
    // TTL (2h) expires. Without this, clients keep getting the stale
    // port until the record naturally lapses.
    let rereg_listen = listen_address.clone();
    tokio::spawn(async move {
        let bootstraps = vec![
        "wss://bootstrap-eu.gnoppix.org/ws".to_string(),
        "wss://bootstrap-asia.gnoppix.org/ws".to_string(),
        "wss://bootstrap-us.gnoppix.org/ws".to_string(),
        ];
        // First re-publish quickly (within ~10s) to overwrite any stale
        // bundle left by a previous instance, then settle into a 5-min cadence.
        let mut first = true;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(if first { 10 } else { 300 })).await;
            first = false;
            for url in &bootstraps {
                if let Err(e) = publish_service_bundle(url, &rereg_listen).await {
                    warn!("Periodic re-publish to {} failed: {}", url, e);
                }
            }
        }
    });

    info!("Waiting for P2P connections...");
    info!("Press Ctrl+C to stop");

    // Accept connections
    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let config_clone = config.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, config_clone).await {
                warn!("Connection error: {}", e);
            }
        });
    }
}

/// Publish the reflector's public service bundle to the opaque cert store on
/// the bootstrap servers (DESIGN.md §6 exception + §4.2). The bundle carries
/// `{cert, vk, kyber_enc, fp, address}` under key `cert:<H(fp)>` — the same
/// opaque blob store every client uses. The server stores it opaquely: it sees
/// the public cert + an encrypted address field, never a plaintext `addr:ip`
/// record. Any client may read it (the key is well-known), which is what makes
/// the reflector reachable without a contact entry. We still solve PoW so the
/// publish is accepted whether or not the server enforces it.
async fn publish_service_bundle(bootstrap_url: &str, listen_address: &str) -> Result<()> {
    use sha2::{Digest, Sha256};

    let (ws_stream, _response) = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        tokio_tungstenite::connect_async(bootstrap_url),
    )
    .await
    .map_err(|_| anyhow!("Timeout connecting to bootstrap {}", bootstrap_url))?
    .map_err(|e| anyhow!("Failed to connect to bootstrap: {}", e))?;

    let mut ws_tx = ws_stream;

    // Deterministic ML-KEM enc key derived from the reflector's null_id, so a
    // client that wants to KEM-encapsulate to the published key gets a stable
    // target (mirrors client/src/main.rs derive from add-sealed-sender-kyber-seed).
    let kyber_enc_b64 = {
        let hash = Sha256::digest(REFLECTOR_NULL_ID.as_bytes());
        let hk = hkdf::Hkdf::<Sha256>::new(None, &hash);
        let mut seed = [0u8; 64];
        hk.expand(b"add-sealed-sender-kyber-seed", &mut seed)
            .map_err(|_| anyhow!("HKDF expand failed"))?;
        let kp = add_crypto::kyber::KyberKeypair::from_seed(&seed)
            .map_err(|e| anyhow!("kyber keypair from seed: {}", e))?;
        add_crypto::kyber::encode_enc_key(&kp.enc)
    };

    let (sk_seed, vk_b64) = load_reflector_signing_key()?;

    // Bundle published to the opaque store. `cert` is empty for the reflector
    // (it has no OpenPGP cert); `vk` is the authoritative verifying key the
    // client pins, and `address` is its advertised ws:// endpoint.
    let bundle = serde_json::json!({
        "cert": "",
        "vk": vk_b64,
        "kyber_enc": kyber_enc_b64,
        "fp": REFLECTOR_FINGERPRINT,
        "address": listen_address,
    })
    .to_string();
    let value_b64 = base64_standard.encode(bundle.as_bytes());

    let key = format!("cert:{}", hex::encode(Sha256::digest(REFLECTOR_FINGERPRINT.as_bytes())));

    let sign_data = format!("{}|{}|{}", key, value_b64, REFLECTOR_FINGERPRINT);
    let sig = {
        use add_crypto_pq::{MlDsa87KeyPair, sign_ml_dsa87};
        let seed_arr: [u8; 32] = sk_seed.as_slice().try_into()
            .map_err(|_| anyhow!("Invalid seed length"))?;
        let kp = MlDsa87KeyPair::from_seed(&seed_arr)?;
        sign_ml_dsa87(sign_data.as_bytes(), &kp.signing_key())?
    };

    // PoW: solve to seq==0 difficulty (8) — the server uses ADDR_POW_DIFFICULTY
    // for `cert:` keys at seq==0. Difficulty 8 is fast (sub-second) and is what
    // the server enforces, so matching it exactly keeps the publish quick.
    let pow_data = format!("{}|{}|{}|{}", key, value_b64, REFLECTOR_FINGERPRINT, 0);
    let pow_nonce: u64 = {
        tokio::task::spawn_blocking({
            let pd = pow_data.clone();
            move || {
                add_dht_core::pow_solve(
                    &pd,
                    add_protocol::constants::ADDR_POW_DIFFICULTY,
                    2_000_000,
                    REFLECTOR_FINGERPRINT.as_bytes(),
                )
            }
        })
        .await
        .map_err(|e| anyhow!("PoW task error: {}", e))?
        .map_err(|e| anyhow!("PoW solve error: {}", e))?
        .ok_or_else(|| anyhow!("Could not solve PoW in time"))?
    };

    let req = add_protocol::envelope::WireEnvelope {
        msg_type: "blob-put".to_string(),
        msg_id: uuid_hex(),
        ts: chrono::Utc::now().timestamp() as f64,
        sig: sig.clone(),
        payload: {
            let mut m = serde_json::Map::new();
            m.insert("key".to_string(), serde_json::Value::String(key));
            m.insert("value".to_string(), serde_json::Value::String(value_b64));
            m.insert("sig".to_string(), serde_json::Value::String(sig));
            m.insert("publisher_fp".to_string(), serde_json::Value::String(REFLECTOR_FINGERPRINT.to_string()));
            // Self-asserted verifying key — the server binds it to publisher_fp
            // before accepting the cert blob (cert-store MITM defense).
            m.insert("publisher_verifying_key".to_string(), serde_json::Value::String(vk_b64.clone()));
            m.insert("ttl".to_string(), serde_json::Value::Number(serde_json::Number::from(add_protocol::constants::ADDR_TTL)));
            m.insert("nonce".to_string(), serde_json::Value::Number(serde_json::Number::from(pow_nonce as i64)));
            m.insert("vk".to_string(), serde_json::Value::String(vk_b64.clone()));
            m.insert("kyber_enc".to_string(), serde_json::Value::String(kyber_enc_b64.clone()));
            serde_json::Value::Object(m)
        },
    };

    ws_tx
        .send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::to_string(&req)?.into(),
        ))
        .await?;
    info!("Published public service bundle to {}", bootstrap_url);

    Ok(())
}

/// Handle incoming P2P connection - echo messages back
async fn handle_connection(stream: tokio::net::TcpStream, config: BotConfig) -> Result<()> {
    use tokio_tungstenite::tungstenite::Message;

    let ws_stream = tokio_tungstenite::accept_async(stream).await?;
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // Read hello
    if let Some(Ok(Message::Text(hello_text))) = ws_rx.next().await {
        let hello: serde_json::Value = serde_json::from_str(&hello_text)?;

        // The client sends `msg_type` (WireEnvelope field); be tolerant of a
        // bare `type` key too, for compatibility.
        let hello_type = hello
            .get("msg_type")
            .or_else(|| hello.get("type"))
            .and_then(|t| t.as_str());
        if hello_type != Some("p2p-hello") {
            return Err(anyhow!("expected p2p-hello"));
        }

        let peer_fp = hello
            .get("public_key")
            .and_then(|k| k.as_str())
            .unwrap_or("unknown");

        // Send hello-ack (signed, mirroring the client handshake C3 fix).
        // The client requires a non-empty `sig` over `p2p-hello-ack:{payload}`
        // verified against the verifying key published in `sender_verifying_key`.
        let mut ack = add_protocol::envelope::WireEnvelope {
            msg_type: "p2p-hello-ack".to_string(),
            payload: serde_json::json!({
                "public_key": REFLECTOR_FINGERPRINT,
                "nonce": 1,
                "pow_bits": 16,
                "server_challenge": uuid_hex(),
                "kyber_enc_key": "",
                "braid": false,
            }),
            msg_id: uuid_hex(),
            ts: chrono::Utc::now().timestamp() as f64,
            sig: String::new(),
        };
        // Generate an ephemeral ML-KEM-1024 keypair so the client can do a real
        // KEM encapsulation (the reflector is an echo bot: it never decapsulates;
        // it simply bounces the sealed ciphertext back for a latency/loopback test).
        let kyber_enc_b64 = {
            let kp = add_crypto::kyber::KyberKeypair::generate()
                .map_err(|e| anyhow!("reflector kyber gen failed: {}", e))?;
            add_crypto::kyber::encode_enc_key(&kp.enc)
        };
        ack.payload["kyber_enc_key"] = serde_json::Value::String(kyber_enc_b64);
        let ack_sig_data = format!("p2p-hello-ack:{}\n", ack.payload);
        let sig = {
            use add_crypto_pq::MlDsa87KeyPair;

            // Load signing key from seed file (persists identity across reboots)
            let (sk_seed, vk_b64) = load_reflector_signing_key()?;
            let seed_arr: [u8; 32] = sk_seed.as_slice().try_into()
                .map_err(|_| anyhow!("Invalid seed length"))?;
            let kp = MlDsa87KeyPair::from_seed(&seed_arr)?;
            let sk = kp.signing_key();
            let vk = kp.verifying_key();
            ack.payload["sender_verifying_key"] = serde_json::Value::String(vk_b64);
            add_dht_core::crypto_helpers::cache_verifying_key(REFLECTOR_FINGERPRINT, &vk);
            add_dht_core::crypto_helpers::sign_data(&ack_sig_data, &sk)
                .map_err(|e| anyhow!("{}", e))?
        };
        ack.sig = sig;
        ws_tx
            .send(Message::Text(serde_json::to_string(&ack)?.into()))
            .await?;

        // Read messages and echo back. The client may send additional
        // frames before/around the actual message (e.g. a `delivery-token`
        // envelope for sealed-sender). Loop and skip any frame that is not a
        // `p2p-message` so we don't drop the real message and reset the peer.
        let mut echoed = false;
        while let Some(frame) = ws_rx.next().await {
            let msg_text = match frame {
                Ok(Message::Text(t)) => t,
                Ok(Message::Close(_)) | Err(_) => break,
                _ => continue,
            };
            let msg: serde_json::Value = match serde_json::from_str(&msg_text) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Tolerant of `msg_type` (WireEnvelope) or bare `type`.
            let msg_type = msg
                .get("msg_type")
                .or_else(|| msg.get("type"))
                .and_then(|t| t.as_str());
            if msg_type != Some("p2p-message") {
                // Not the message we echo (e.g. delivery-token); keep reading.
                continue;
            }

            // The client sends ciphertext inside `payload.ciphertext` (WireEnvelope);
            // fall back to a top-level `ciphertext` for compatibility.
            let ciphertext = msg
                .get("payload")
                .and_then(|p| p.get("ciphertext"))
                .and_then(|c| c.as_str())
                .or_else(|| msg.get("ciphertext").and_then(|c| c.as_str()))
                .unwrap_or("");

            // Echo back with prefix
            let echoed_text = format!("{}{}", config.reflector.prefix, ciphertext);

            let echo_msg = serde_json::json!({
                "type": "p2p-message",
                "ciphertext": echoed_text,
                "recipient": peer_fp,
            });
            ws_tx
                .send(Message::Text(echo_msg.to_string().into()))
                .await?;

            // Send ack
            let ack_msg = serde_json::json!({
                "type": "p2p-ack",
                "seq": 1,
            });
            ws_tx
                .send(Message::Text(ack_msg.to_string().into()))
                .await?;

            // Send read receipt
            let receipt_msg = serde_json::json!({
                "type": "p2p-receipt",
                "msg_hash": sha256_hex(ciphertext),
                "received_at": chrono::Utc::now().timestamp() as f64,
                "seq": 1,
            });
            ws_tx
                .send(Message::Text(receipt_msg.to_string().into()))
                .await?;
            echoed = true;
            break;
        }
        if echoed {}
    }

    Ok(())
}

fn sha256_hex(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

fn uuid_hex() -> String {
    format!("{}", uuid::Uuid::new_v4().hyphenated())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::Message;

    /// End-to-end echo test against handle_connection over a real TCP socket.
    /// Uses /tmp seed path since /var/lib/add may not be writable.
    #[tokio::test]
    async fn test_reflector_echo_roundtrip() {
        // Use /tmp for test seed
        let test_seed_path = "/tmp/add-reflector-test-seed";
        let _ = std::fs::remove_file(test_seed_path);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = BotConfig::default();
        let _prefix = config.reflector.prefix.clone();
        let own_fp = "TESTFP00000000000000000000000000000000";

        let _server = tokio::spawn(async move {
            // Set env for this test
            unsafe { std::env::set_var("ADD_REFLECTOR_SEED_PATH", test_seed_path); }
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, config).await.unwrap();
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut ws, _) = tokio_tungstenite::client_async("ws://127.0.0.1/", tcp)
            .await
            .unwrap();

        // 1) hello
        ws.send(Message::Text(
            serde_json::json!({ "type": "p2p-hello", "public_key": own_fp })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();

        // 2) hello-ack
        let ack = ws.next().await.unwrap().unwrap();
        let ack: serde_json::Value = serde_json::from_str(ack.to_text().unwrap()).unwrap();
        assert_eq!(ack["type"], "p2p-hello-ack");
        assert_eq!(ack["payload"]["public_key"], REFLECTOR_FINGERPRINT);
        assert_eq!(ack["payload"]["nonce"], 1);
        assert_eq!(ack["payload"]["pow_bits"], 16);

        // 3) send a message
        let plaintext = "hello-world";
        ws.send(Message::Text(
            serde_json::json!({ "type": "p2p-message", "ciphertext": plaintext })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();

        // 4) verify echo
        let echoed = ws.next().await.unwrap().unwrap();
        let echoed: serde_json::Value = serde_json::from_str(echoed.to_text().unwrap()).unwrap();
        assert_eq!(echoed["type"], "p2p-message");
        // Prefix is 🤖 [Reflector Echo]: which starts with 🤖 (U+1F916)
        assert!(echoed["ciphertext"].as_str().unwrap().starts_with("🤖") ||
                echoed["ciphertext"].as_str().unwrap().starts_with("ECHO:"));
    }

    /// Test that reflector rejects non-hello messages
    #[tokio::test]
    async fn test_reflector_rejects_non_hello() {
        let test_seed_path = "/tmp/add-reflector-test-seed-2";
        let _ = std::fs::remove_file(test_seed_path);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = BotConfig::default();

        let _server = tokio::spawn(async move {
            unsafe { std::env::set_var("ADD_REFLECTOR_SEED_PATH", test_seed_path); }
            let (stream, _) = listener.accept().await.unwrap();
            let result = handle_connection(stream, config).await;
            assert!(result.is_err());
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut ws, _) = tokio_tungstenite::client_async("ws://127.0.0.1/", tcp)
            .await
            .unwrap();

        // Send non-hello message (will cause connection to close/ignore)
        ws.send(Message::Text(
            serde_json::json!({ "type": "other" })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    }
}