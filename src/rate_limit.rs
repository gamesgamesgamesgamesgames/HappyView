use arc_swap::ArcSwap;
use dashmap::DashMap;
use ipnet::IpNet;
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub struct RateLimitConfig {
    pub capacity: u32,
    pub refill_rate: f64,
}

pub enum CheckResult {
    Allowed {
        remaining: u32,
        limit: u32,
        reset: u64,
    },
    Limited {
        retry_after: u64,
        limit: u32,
        reset: u64,
    },
    Disabled,
}

struct TokenBucket {
    tokens: f64,
    capacity: u32,
    refill_rate: f64,
    last_refill: Instant,
    last_access: Instant,
}

pub struct RateLimiter {
    enabled: AtomicBool,
    buckets: DashMap<String, TokenBucket>,
    global_config: ArcSwap<RateLimitConfig>,
    overrides: ArcSwap<HashMap<String, RateLimitConfig>>,
    allowlist: ArcSwap<Vec<IpNet>>,
}

pub struct RateLimiterState {
    pub enabled: bool,
    pub global: RateLimitConfig,
    pub overrides: HashMap<String, RateLimitConfig>,
    pub allowlist: Vec<IpNet>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl RateLimiter {
    pub fn new(
        enabled: bool,
        global: RateLimitConfig,
        overrides: HashMap<String, RateLimitConfig>,
        allowlist: Vec<IpNet>,
    ) -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(enabled),
            buckets: DashMap::new(),
            global_config: ArcSwap::new(Arc::new(global)),
            overrides: ArcSwap::new(Arc::new(overrides)),
            allowlist: ArcSwap::new(Arc::new(allowlist)),
        })
    }

    pub fn check(&self, key: &str, method: Option<&str>, client_ip: Option<IpAddr>) -> CheckResult {
        if !self.enabled.load(Ordering::Relaxed) {
            return CheckResult::Disabled;
        }

        if let Some(ip) = client_ip {
            let list = self.allowlist.load();
            for net in list.iter() {
                if net.contains(&ip) {
                    return CheckResult::Disabled;
                }
            }
        }

        let overrides = self.overrides.load();
        let global = self.global_config.load();

        let (capacity, refill_rate) = if let Some(method) = method {
            if let Some(cfg) = overrides.get(method) {
                (cfg.capacity, cfg.refill_rate)
            } else {
                (global.capacity, global.refill_rate)
            }
        } else {
            (global.capacity, global.refill_rate)
        };

        let now = Instant::now();

        let mut bucket = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: capacity as f64,
                capacity,
                refill_rate,
                last_refill: now,
                last_access: now,
            });

        // Hot-reload config changes
        bucket.capacity = capacity;
        bucket.refill_rate = refill_rate;

        // Refill tokens
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_rate).min(capacity as f64);
        bucket.last_refill = now;
        bucket.last_access = now;

        let reset_secs = if bucket.tokens < capacity as f64 {
            ((capacity as f64 - bucket.tokens) / refill_rate).ceil() as u64
        } else {
            0
        };
        let reset = now_unix() + reset_secs;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            CheckResult::Allowed {
                remaining: bucket.tokens.floor() as u32,
                limit: capacity,
                reset,
            }
        } else {
            let retry_after = ((1.0 - bucket.tokens) / refill_rate).ceil() as u64;
            CheckResult::Limited {
                retry_after,
                limit: capacity,
                reset: now_unix() + ((capacity as f64) / refill_rate).ceil() as u64,
            }
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn update_config(
        &self,
        global: RateLimitConfig,
        overrides: HashMap<String, RateLimitConfig>,
    ) {
        self.global_config.store(Arc::new(global));
        self.overrides.store(Arc::new(overrides));
    }

    pub fn update_allowlist(&self, entries: Vec<IpNet>) {
        self.allowlist.store(Arc::new(entries));
    }

    pub async fn spawn_cleanup(self: Arc<Self>) {
        let interval = tokio::time::Duration::from_secs(60);
        let stale_threshold = std::time::Duration::from_secs(300); // 5 minutes
        loop {
            tokio::time::sleep(interval).await;
            let now = Instant::now();
            self.buckets
                .retain(|_, bucket| now.duration_since(bucket.last_access) < stale_threshold);
        }
    }

    pub async fn load_from_db(db: &PgPool) -> RateLimiterState {
        // Load enabled flag
        let enabled: bool = sqlx::query_scalar::<_, String>(
            "SELECT value FROM rate_limit_settings WHERE key = 'enabled'",
        )
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .map(|v| v == "true")
        .unwrap_or(true);

        // Load rate limit configs
        let rows: Vec<(Option<String>, i32, f32)> =
            sqlx::query_as("SELECT method, capacity, refill_rate FROM rate_limits")
                .fetch_all(db)
                .await
                .unwrap_or_default();

        let mut global = RateLimitConfig {
            capacity: 100,
            refill_rate: 2.0,
        };
        let mut overrides = HashMap::new();

        for (method, capacity, refill_rate) in rows {
            let config = RateLimitConfig {
                capacity: capacity as u32,
                refill_rate: refill_rate as f64,
            };
            match method {
                None => global = config,
                Some(m) => {
                    overrides.insert(m, config);
                }
            }
        }

        // Load allowlist
        let cidr_rows: Vec<(String,)> = sqlx::query_as("SELECT cidr FROM rate_limit_allowlist")
            .fetch_all(db)
            .await
            .unwrap_or_default();

        let allowlist: Vec<IpNet> = cidr_rows
            .into_iter()
            .filter_map(|(cidr,)| cidr.parse().ok())
            .collect();

        RateLimiterState {
            enabled,
            global,
            overrides,
            allowlist,
        }
    }

    /// Reload all config from DB and apply to the live limiter.
    pub async fn reload_from_db(&self, db: &PgPool) {
        let state = Self::load_from_db(db).await;
        self.set_enabled(state.enabled);
        self.update_config(state.global, state.overrides);
        self.update_allowlist(state.allowlist);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_allow_and_exhaust() {
        let rl = RateLimiter::new(
            true,
            RateLimitConfig {
                capacity: 3,
                refill_rate: 1.0,
            },
            HashMap::new(),
            vec![],
        );

        // Should allow 3 requests (bucket starts full)
        for _ in 0..3 {
            assert!(matches!(
                rl.check("k", None, None),
                CheckResult::Allowed { .. }
            ));
        }
        // 4th should be limited
        assert!(matches!(
            rl.check("k", None, None),
            CheckResult::Limited { .. }
        ));
    }

    #[test]
    fn disabled_returns_disabled() {
        let rl = RateLimiter::new(
            false,
            RateLimitConfig {
                capacity: 1,
                refill_rate: 1.0,
            },
            HashMap::new(),
            vec![],
        );
        assert!(matches!(rl.check("k", None, None), CheckResult::Disabled));
    }

    #[test]
    fn allowlisted_ip_bypasses() {
        let rl = RateLimiter::new(
            true,
            RateLimitConfig {
                capacity: 1,
                refill_rate: 0.001,
            },
            HashMap::new(),
            vec!["10.0.0.0/8".parse().unwrap()],
        );

        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        // Even after exhausting, allowlisted IP gets Disabled
        assert!(matches!(
            rl.check("k", None, Some(ip)),
            CheckResult::Disabled
        ));
    }

    #[test]
    fn method_override_applies() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "com.atproto.repo.uploadBlob".to_string(),
            RateLimitConfig {
                capacity: 2,
                refill_rate: 0.001,
            },
        );

        let rl = RateLimiter::new(
            true,
            RateLimitConfig {
                capacity: 100,
                refill_rate: 100.0,
            },
            overrides,
            vec![],
        );

        // Override has capacity 2
        assert!(matches!(
            rl.check("k", Some("com.atproto.repo.uploadBlob"), None),
            CheckResult::Allowed { limit: 2, .. }
        ));
        assert!(matches!(
            rl.check("k", Some("com.atproto.repo.uploadBlob"), None),
            CheckResult::Allowed { limit: 2, .. }
        ));
        assert!(matches!(
            rl.check("k", Some("com.atproto.repo.uploadBlob"), None),
            CheckResult::Limited { limit: 2, .. }
        ));
    }

    #[test]
    fn toggle_enabled() {
        let rl = RateLimiter::new(
            true,
            RateLimitConfig {
                capacity: 1,
                refill_rate: 1.0,
            },
            HashMap::new(),
            vec![],
        );
        assert!(rl.is_enabled());
        rl.set_enabled(false);
        assert!(!rl.is_enabled());
        assert!(matches!(rl.check("k", None, None), CheckResult::Disabled));
    }
}
