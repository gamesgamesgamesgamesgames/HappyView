use arc_swap::ArcSwap;
use dashmap::DashMap;
use ipnet::IpNet;
use sqlx::AnyPool;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub struct RateLimitConfig {
    pub capacity: u32,
    pub refill_rate: f64,
    pub default_query_cost: u32,
    pub default_procedure_cost: u32,
    pub default_proxy_cost: u32,
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
    allowlist: ArcSwap<Vec<IpNet>>,
}

pub struct RateLimiterState {
    pub enabled: bool,
    pub global: RateLimitConfig,
    pub allowlist: Vec<IpNet>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl RateLimiter {
    pub fn new(enabled: bool, global: RateLimitConfig, allowlist: Vec<IpNet>) -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(enabled),
            buckets: DashMap::new(),
            global_config: ArcSwap::new(Arc::new(global)),
            allowlist: ArcSwap::new(Arc::new(allowlist)),
        })
    }

    pub fn check(&self, key: &str, cost: u32, client_ip: Option<IpAddr>) -> CheckResult {
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

        let global = self.global_config.load();
        let capacity = global.capacity;
        let refill_rate = global.refill_rate;
        let cost_f64 = cost as f64;

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

        if bucket.tokens >= cost_f64 {
            bucket.tokens -= cost_f64;
            CheckResult::Allowed {
                remaining: bucket.tokens.floor() as u32,
                limit: capacity,
                reset,
            }
        } else {
            let retry_after = ((cost_f64 - bucket.tokens) / refill_rate).ceil() as u64;
            CheckResult::Limited {
                retry_after,
                limit: capacity,
                reset: now_unix() + ((capacity as f64) / refill_rate).ceil() as u64,
            }
        }
    }

    /// Get the default cost for a given request type.
    pub fn default_cost_for_type(&self, request_type: &str) -> u32 {
        let config = self.global_config.load();
        match request_type {
            "query" => config.default_query_cost,
            "procedure" => config.default_procedure_cost,
            "proxy" => config.default_proxy_cost,
            _ => 1,
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn update_config(&self, global: RateLimitConfig) {
        self.global_config.store(Arc::new(global));
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

    pub async fn load_from_db(db: &AnyPool) -> RateLimiterState {
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

        // Load global rate limit config (method IS NULL row)
        let row: Option<(i32, f32, i32, i32, i32)> = sqlx::query_as(
            "SELECT capacity, refill_rate, default_query_cost, default_procedure_cost, default_proxy_cost FROM rate_limits WHERE method IS NULL",
        )
        .fetch_optional(db)
        .await
        .unwrap_or(None);

        let global = match row {
            Some((capacity, refill_rate, query_cost, procedure_cost, proxy_cost)) => {
                RateLimitConfig {
                    capacity: capacity as u32,
                    refill_rate: refill_rate as f64,
                    default_query_cost: query_cost as u32,
                    default_procedure_cost: procedure_cost as u32,
                    default_proxy_cost: proxy_cost as u32,
                }
            }
            None => RateLimitConfig {
                capacity: 100,
                refill_rate: 2.0,
                default_query_cost: 1,
                default_procedure_cost: 1,
                default_proxy_cost: 1,
            },
        };

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
            allowlist,
        }
    }

    /// Reload all config from DB and apply to the live limiter.
    pub async fn reload_from_db(&self, db: &AnyPool) {
        let state = Self::load_from_db(db).await;
        self.set_enabled(state.enabled);
        self.update_config(state.global);
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
                default_query_cost: 1,
                default_procedure_cost: 1,
                default_proxy_cost: 1,
            },
            vec![],
        );

        // Should allow 3 requests (bucket starts full, cost=1 each)
        for _ in 0..3 {
            assert!(matches!(
                rl.check("k", 1, None),
                CheckResult::Allowed { .. }
            ));
        }
        // 4th should be limited
        assert!(matches!(
            rl.check("k", 1, None),
            CheckResult::Limited { .. }
        ));
    }

    #[test]
    fn cost_deducts_multiple_tokens() {
        let rl = RateLimiter::new(
            true,
            RateLimitConfig {
                capacity: 10,
                refill_rate: 1.0,
                default_query_cost: 1,
                default_procedure_cost: 1,
                default_proxy_cost: 1,
            },
            vec![],
        );

        // Cost of 5 should allow 2 requests (10 tokens total)
        assert!(matches!(
            rl.check("k", 5, None),
            CheckResult::Allowed { remaining: 5, .. }
        ));
        assert!(matches!(
            rl.check("k", 5, None),
            CheckResult::Allowed { remaining: 0, .. }
        ));
        // 3rd should be limited
        assert!(matches!(
            rl.check("k", 5, None),
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
                default_query_cost: 1,
                default_procedure_cost: 1,
                default_proxy_cost: 1,
            },
            vec![],
        );
        assert!(matches!(rl.check("k", 1, None), CheckResult::Disabled));
    }

    #[test]
    fn allowlisted_ip_bypasses() {
        let rl = RateLimiter::new(
            true,
            RateLimitConfig {
                capacity: 1,
                refill_rate: 0.001,
                default_query_cost: 1,
                default_procedure_cost: 1,
                default_proxy_cost: 1,
            },
            vec!["10.0.0.0/8".parse().unwrap()],
        );

        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        // Even after exhausting, allowlisted IP gets Disabled
        assert!(matches!(rl.check("k", 1, Some(ip)), CheckResult::Disabled));
    }

    #[test]
    fn default_cost_for_type() {
        let rl = RateLimiter::new(
            true,
            RateLimitConfig {
                capacity: 100,
                refill_rate: 10.0,
                default_query_cost: 2,
                default_procedure_cost: 5,
                default_proxy_cost: 3,
            },
            vec![],
        );

        assert_eq!(rl.default_cost_for_type("query"), 2);
        assert_eq!(rl.default_cost_for_type("procedure"), 5);
        assert_eq!(rl.default_cost_for_type("proxy"), 3);
        assert_eq!(rl.default_cost_for_type("unknown"), 1);
    }

    #[test]
    fn toggle_enabled() {
        let rl = RateLimiter::new(
            true,
            RateLimitConfig {
                capacity: 1,
                refill_rate: 1.0,
                default_query_cost: 1,
                default_procedure_cost: 1,
                default_proxy_cost: 1,
            },
            vec![],
        );
        assert!(rl.is_enabled());
        rl.set_enabled(false);
        assert!(!rl.is_enabled());
        assert!(matches!(rl.check("k", 1, None), CheckResult::Disabled));
    }
}
