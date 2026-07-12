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
use tracing::{debug, info, warn};
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
/// Private key for DHT signing (ML-DSA-87 PKCS8 base64)
const REFLECTOR_PRIVATE_KEY: &str = include_str!("../reflector_private_ml_dsa87.key");

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

    // Register addr_record in DHT with all bootstrap servers
    let bootstrap_urls = vec![
        "wss://bootstrap-eu.gnoppix.org/ws".to_string(),
        "wss://bootstrap-asia.gnoppix.org/ws".to_string(),
        "wss://bootstrap-us.gnoppix.org/ws".to_string(),
    ];

    for url in &bootstrap_urls {
        if let Err(e) = register_addr_record(url, &listen_address).await {
            warn!("Failed to register to {}: {}", url, e);
        } else {
            info!("Registered address in DHT on {}", url);
        }
    }
    info!("Registered address in DHT for direct P2P discovery");

    if args.once {
        info!("Single cycle complete - exiting");
        return Ok(());
    }

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

/// Register the reflector's listening address in the DHT using WireEnvelope format
async fn register_addr_record(bootstrap_url: &str, listen_address: &str) -> Result<()> {
    let (ws_stream, _response) = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        tokio_tungstenite::connect_async(bootstrap_url),
    )
    .await
    .map_err(|_| anyhow!("Timeout connecting to bootstrap {}", bootstrap_url))?
    .map_err(|e| anyhow!("Failed to connect to bootstrap: {}", e))?;

    // Do not split()+drop the read half: that stalls writes (pongs never read).
    // Send on the unified stream, mirroring the client's working ws_connect() path.
    let mut ws_tx = ws_stream;

    // Calculate key for addr_record: "addr:{null_id}"
    let addr_key = format!("addr:{}", REFLECTOR_NULL_ID);
    let value_b64 = base64_standard.encode(listen_address);
    let salt = uuid_hex();
    // Monotonic seq (timestamp) so re-registration after a restart updates the
    // record instead of being rejected as a stale (duplicate) seq=0 put.
    let seq: i64 = chrono::Utc::now().timestamp();

    // Solve PoW (difficulty 8 for addr records; bounded internally by wall-clock).
    let pow_nonce: u64 = {
        // SECURITY FIX (M11): salt PoW with the publisher's own fingerprint so
        // the server (which validates with the same publisher_fp) reproduces
        // the identical Argon2id salt.
        let pow_data = format!("{}|{}|{}|{}", addr_key, value_b64, salt, seq);
        tokio::task::spawn_blocking(move || {
            add_dht_core::pow_solve(
                &pow_data,
                add_protocol::constants::ADDR_POW_DIFFICULTY,
                10_000_000,
                REFLECTOR_FINGERPRINT.as_bytes(),
            )
        })
        .await
        .map_err(|e| anyhow!("PoW task error: {}", e))?
        .map_err(|e| anyhow!("PoW solve error: {}", e))?
        .ok_or_else(|| anyhow!("Could not solve PoW in time"))?
    };

    // Sign the DHT put request with ML-DSA-87
    let mut reflector_vk_b64: Option<String>;
    let sign_data = format!("{}|{}|{}|{}|{}", addr_key, value_b64, salt, seq, pow_nonce);
    let sig = {
        use add_crypto_pq::{MlDsa87SigningKey, sign_ml_dsa87};
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as base64_standard;
        use ml_dsa::KeyExport;
        use ml_dsa::KeyInit;

        // Load ML-DSA-87 private key for DHT registration
        let sk_bytes = base64_standard
            .decode(REFLECTOR_PRIVATE_KEY)
            .map_err(|e| anyhow!("Failed to decode private key: {}", e))?;
        let sk = MlDsa87SigningKey::new_from_slice(&sk_bytes)
            .map_err(|e| anyhow!("Failed to load ML-DSA-87 private key: {}", e))?;
        let vk = ml_dsa::Keypair::verifying_key(&sk).clone();
        let vk_b64 = base64_standard.encode(vk.to_bytes());
        // Expose the verifying key so the bootstrap can verify without a
        // pre-populated key cache (mirrors the client's dht_register).
        reflector_vk_b64 = Some(vk_b64);

        sign_ml_dsa87(sign_data.as_bytes(), &sk)
            .map_err(|e| anyhow!("ML-DSA-87 sign failed: {}", e))?
    };

    // Create dht-put message with proper publisher_fp for signature verification
    let req = add_protocol::envelope::WireEnvelope {
        msg_type: "dht-put".to_string(),
        msg_id: uuid_hex(),
        ts: chrono::Utc::now().timestamp() as f64,
        sig,
        payload: {
            let mut m = serde_json::Map::new();
            m.insert("key".to_string(), serde_json::Value::String(addr_key));
            m.insert("value".to_string(), serde_json::Value::String(value_b64));
            m.insert("salt".to_string(), serde_json::Value::String(salt));
            m.insert("seq".to_string(), serde_json::Value::Number(seq.into()));
            m.insert(
                "nonce".to_string(),
                serde_json::Value::Number(pow_nonce.into()),
            );
            m.insert(
                "publisher_fp".to_string(),
                serde_json::Value::String(REFLECTOR_FINGERPRINT.to_string()),
            );
            if let Some(vk) = reflector_vk_b64.take() {
                m.insert(
                    "publisher_verifying_key".to_string(),
                    serde_json::Value::String(vk),
                );
            }
            serde_json::Value::Object(m)
        },
    };

    ws_tx
        .send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::to_string(&req)?.into(),
        ))
        .await?;
    info!("Sent dht-put registration to {}", bootstrap_url);

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
            use add_crypto_pq::MlDsa87SigningKey;
            use base64::Engine as _;
            use base64::engine::general_purpose::STANDARD as base64_standard;
            use ml_dsa::KeyExport;
            use ml_dsa::KeyInit;

            let vk_bytes = base64_standard
                .decode(REFLECTOR_PRIVATE_KEY)
                .map_err(|e| anyhow!("Failed to decode private key: {}", e))?;
            let sk = MlDsa87SigningKey::new_from_slice(&vk_bytes)
                .map_err(|e| anyhow!("Failed to load ML-DSA-87 private key: {}", e))?;
            let vk = ml_dsa::Keypair::verifying_key(&sk).clone();
            let vk_b64 = base64_standard.encode(vk.to_bytes());
            ack.payload["sender_verifying_key"] = serde_json::Value::String(vk_b64.clone());
            add_dht_core::crypto_helpers::cache_verifying_key(REFLECTOR_FINGERPRINT, &vk);
            add_dht_core::crypto_helpers::sign_data(&ack_sig_data, &sk)
                .map_err(|e| anyhow!("hello-ack sign failed: {}", e))?
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
        if echoed {
        }
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
    /// Exercises the reflector protocol: p2p-hello -> p2p-hello-ack ->
    /// p2p-message -> echoed p2p-message (prefix prepended) + p2p-ack + p2p-receipt.
    #[tokio::test]
    async fn test_reflector_echo_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = BotConfig::default();
        let prefix = config.reflector.prefix.clone();
        let own_fp = "TESTFP00000000000000000000000000000000";

        let server = tokio::spawn(async move {
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

        // 4) echoed p2p-message
        let echo = ws.next().await.unwrap().unwrap();
        let echo: serde_json::Value = serde_json::from_str(echo.to_text().unwrap()).unwrap();
        assert_eq!(echo["type"], "p2p-message");
        let echoed = echo["ciphertext"].as_str().unwrap();
        assert!(echoed.starts_with(&prefix), "echo not prefixed: {echoed}");
        assert_eq!(echoed, format!("{prefix}{plaintext}"));
        assert_eq!(echo["recipient"], own_fp);

        // 5) p2p-ack
        let p2p_ack = ws.next().await.unwrap().unwrap();
        let p2p_ack: serde_json::Value = serde_json::from_str(p2p_ack.to_text().unwrap()).unwrap();
        assert_eq!(p2p_ack["type"], "p2p-ack");
        assert_eq!(p2p_ack["seq"], 1);

        // 6) p2p-receipt
        let receipt = ws.next().await.unwrap().unwrap();
        let receipt: serde_json::Value = serde_json::from_str(receipt.to_text().unwrap()).unwrap();
        assert_eq!(receipt["type"], "p2p-receipt");
        assert_eq!(receipt["msg_hash"], sha256_hex(plaintext));
        assert_eq!(receipt["seq"], 1);

        server.await.unwrap();
    }

    /// The reflector must reject a connection that does not start with p2p-hello.
    #[tokio::test]
    async fn test_reflector_rejects_non_hello() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = BotConfig::default();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // handle_connection returns Err because the first frame isn't p2p-hello
            let res = handle_connection(stream, config).await;
            assert!(res.is_err());
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut ws, _) = tokio_tungstenite::client_async("ws://127.0.0.1/", tcp)
            .await
            .unwrap();
        ws.send(Message::Text(
            serde_json::json!({ "type": "p2p-message", "ciphertext": "x" })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();

        server.await.unwrap();
    }
}
