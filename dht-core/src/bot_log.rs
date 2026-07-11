//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

/// Maximum log file size before rotation (10 MiB).
/// SECURITY FIX (M8): Without rotation, the log file can grow unbounded,
/// potentially filling the disk.
const MAX_LOG_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum number of rotated log files to keep.
const MAX_ROTATED_FILES: usize = 3;

/// Log suspicious bot/scanner activity to bot_connection.log.
///
/// Writes a structured log line similar to nginx access log format:
/// 2026-06-23T14:32:01+00:00 203.0.113.5:54321 SCANNER bad_envelope: invalid JSON
#[derive(Clone)]
pub struct BotLogger {
    log_path: PathBuf,
}

impl BotLogger {
    /// Create a new BotLogger. The log file path defaults to
    /// `~/.add/bot_connection.log`.
    pub fn new(log_path: Option<PathBuf>) -> Self {
        let path = log_path.unwrap_or_else(|| {
            let mut p = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            p.push(".add");
            p.push("bot_connection.log");
            p
        });
        Self { log_path: path }
    }

    /// SECURITY FIX (M8): Check if the log file exceeds the size limit
    /// and rotate it if necessary. Rotated files are named
    /// `bot_connection.log.1`, `.2`, etc.
    fn rotate_if_needed(&self) {
        let Ok(metadata) = fs::metadata(&self.log_path) else {
            return;
        };
        if metadata.len() < MAX_LOG_FILE_SIZE {
            return;
        }

        // Shift existing rotated files: .2 -> .3, .1 -> .2, current -> .1
        for i in (1..=MAX_ROTATED_FILES).rev() {
            let from = if i == 1 {
                self.log_path.clone()
            } else {
                let mut p = self.log_path.clone();
                p.set_extension(format!("log.{}", i - 1));
                p
            };
            let mut to = self.log_path.clone();
            to.set_extension(format!("log.{}", i));
            let _ = fs::rename(&from, &to);
        }

        // Truncate the current file (it was already moved to .1)
        let _ = fs::write(&self.log_path, "");
    }

    /// Log a bot/scanner event.
    pub fn log(&self, peer_ip: &str, peer_port: u16, reason: &str, detail: Option<&str>) {
        let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%z").to_string();
        // Insert colon in timezone offset for readability: +0000 -> +00:00
        let ts = if ts.len() > 5 {
            let (a, b) = ts.split_at(ts.len() - 2);
            format!("{}:{}", a, b)
        } else {
            ts
        };
        let detail_str = detail.map(|d| format!(" ({d})")).unwrap_or_default();
        let log_line = format!("{} {}:{}{} {}", ts, peer_ip, peer_port, detail_str, reason);

        if let Some(parent) = self.log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // SECURITY FIX (M8): Rotate the log file if it has grown too large.
        self.rotate_if_needed();

        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&self.log_path) {
            let _ = writeln!(f, "{}", log_line);
        } else {
            tracing::warn!("could not write to {}", self.log_path.display());
        }
    }
}

/// Thread-safe wrapper around BotLogger.
#[derive(Clone)]
pub struct SharedBotLogger {
    inner: Arc<BotLogger>,
}

impl SharedBotLogger {
    pub fn new(log_path: Option<PathBuf>) -> Self {
        Self {
            inner: Arc::new(BotLogger::new(log_path)),
        }
    }

    pub fn log(&self, peer_ip: &str, peer_port: u16, reason: &str, detail: Option<&str>) {
        self.inner.log(peer_ip, peer_port, reason, detail);
    }
}
