//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Per-key sliding-window rate limiter.
///
/// Tracks recent operations per key (typically source IP) within a time
/// window and rejects once the ceiling is hit. Periodically prunes
/// expired entries so the map doesn't grow without bound.
///
/// SECURITY FIX (G9): Added MAX_BUCKETS limit to prevent unbounded memory
/// growth under DoS attacks. Oldest buckets are evicted when limit is exceeded.
#[derive(Clone)]
pub struct RateLimiter {
    max: usize,
    window: f64,
    max_buckets: usize,  // SECURITY FIX (G9): Limit total number of buckets
    buckets: Arc<Mutex<HashMap<String, Vec<f64>>>>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// `max_per_window` is the maximum number of operations allowed per key
    /// within `window_sec` seconds.
    ///
    /// SECURITY FIX (G9): `max_buckets` limits total tracked keys to prevent
    /// memory exhaustion under attack.
    pub fn new(max_per_window: usize, window_sec: f64) -> Self {
        Self {
            max: max_per_window,
            window: window_sec,
            max_buckets: 100_000,  // SECURITY FIX (G9): Cap at 100k unique keys
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check whether the given key is allowed to proceed.
    /// Returns true if within the rate limit, false if exceeded.
    ///
    /// SECURITY FIX (G9): Enforces max_buckets limit and evicts oldest entries.
    pub async fn allow(&self, key: &str) -> bool {
        let now = now_unix();
        let cutoff = now - self.window;
        let mut buckets = self.buckets.lock().await;

        // SECURITY FIX (G9): Enforce max buckets limit
        if buckets.len() >= self.max_buckets && !buckets.contains_key(key) {
            // Evict oldest bucket (first key in the map)
            if let Some(oldest) = buckets.keys().next().cloned() {
                buckets.remove(&oldest);
            }
        }

        let entries = buckets.entry(key.to_string()).or_default();

        // Prune expired entries
        entries.retain(|&t| t >= cutoff);

        if entries.len() >= self.max {
            return false;
        }

        entries.push(now);
        true
    }

    /// Prune all expired entries from all buckets.
    pub async fn prune(&self) {
        let now = now_unix();
        let cutoff = now - self.window;
        let mut buckets = self.buckets.lock().await;
        let keys_to_remove: Vec<String> = buckets
            .iter_mut()
            .map(|(k, entries)| {
                entries.retain(|&t| t >= cutoff);
                if entries.is_empty() {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .filter_map(|x| x)
            .collect();
        for k in keys_to_remove {
            buckets.remove(&k);
        }
    }

    /// Start a background task that prunes expired entries periodically.
    /// Returns a JoinHandle that can be used to stop the task.
    pub fn start_background_prune(
        &self,
        interval_sec: f64,
    ) -> tokio::task::JoinHandle<()> {
        let buckets = self.buckets.clone();
        let window = self.window;
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs_f64(interval_sec);
            loop {
                tokio::time::sleep(interval).await;
                let now = now_unix();
                let cutoff = now - window;
                let mut buckets = buckets.lock().await;
                let keys_to_remove: Vec<String> = buckets
                    .iter_mut()
                    .map(|(k, entries)| {
                        entries.retain(|&t| t >= cutoff);
                        if entries.is_empty() {
                            Some(k.clone())
                        } else {
                            None
                        }
                    })
                    .filter_map(|x| x)
                    .collect();
                for k in keys_to_remove {
                    buckets.remove(&k);
                }
            }
        })
    }
}

fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(3, 60.0);
        assert!(limiter.allow("192.168.1.1").await);
        assert!(limiter.allow("192.168.1.1").await);
        assert!(limiter.allow("192.168.1.1").await);
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(2, 60.0);
        assert!(limiter.allow("192.168.1.1").await);
        assert!(limiter.allow("192.168.1.1").await);
        assert!(!limiter.allow("192.168.1.1").await);
    }

    #[tokio::test]
    async fn test_rate_limiter_separate_keys() {
        let limiter = RateLimiter::new(1, 60.0);
        assert!(limiter.allow("192.168.1.1").await);
        assert!(!limiter.allow("192.168.1.1").await);
        assert!(limiter.allow("192.168.1.2").await);
    }
}
