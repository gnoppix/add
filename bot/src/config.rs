//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BotConfig {
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub reflector: ReflectorConfig,
    #[serde(default)]
    pub network: NetworkConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    #[serde(default)]
    pub key_dir: String,
    #[serde(default)]
    pub null_id: String,
    #[serde(default)]
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflectorConfig {
    #[serde(default = "default_prefix")]
    pub prefix: String,
    #[serde(default)]
    pub default_ttl: Option<String>,
    #[serde(default = "default_known_bots")]
    pub known_bot_prefixes: Vec<String>,
    #[serde(default = "default_true")]
    pub inherit_ttl: bool,
    #[serde(default = "default_true")]
    pub send_read_receipts: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_bootstrap")]
    pub bootstrap_url: String,
    #[serde(default = "default_polling_interval")]
    pub polling_interval: u64,
}

fn default_bootstrap() -> String {
    "wss://bootstrap-eu.gnoppix.org/ws".to_string()
}

fn default_prefix() -> String {
    "🤖 [Reflector Echo]: ".to_string()
}

fn default_known_bots() -> Vec<String> {
    vec!["🤖 [Reflector Echo]: ".to_string()]
}

fn default_true() -> bool {
    true
}

fn default_polling_interval() -> u64 {
    30
}

impl BotConfig {
    pub async fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            let config = Self::default();
            config.save(path).await?;
            return Ok(config);
        }

        let content = tokio::fs::read_to_string(path).await?;
        let config: BotConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub async fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let content = toml::to_string_pretty(self)?;
        tokio::fs::write(path, content).await?;
        Ok(())
    }
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            key_dir: ".add/bot".to_string(),
            null_id: String::new(),
            fingerprint: String::new(),
        }
    }
}

impl Default for ReflectorConfig {
    fn default() -> Self {
        Self {
            prefix: default_prefix(),
            default_ttl: None,
            known_bot_prefixes: default_known_bots(),
            inherit_ttl: true,
            send_read_receipts: true,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bootstrap_url: default_bootstrap(),
            polling_interval: default_polling_interval(),
        }
    }
}
