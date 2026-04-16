use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Domain {
    pub id: String,
    pub url: String,
    pub is_primary: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl Domain {
    pub fn host(&self) -> &str {
        let after_scheme = self
            .url
            .strip_prefix("https://")
            .or_else(|| self.url.strip_prefix("http://"))
            .unwrap_or(&self.url);
        after_scheme.split(':').next().unwrap_or(after_scheme)
    }
}

#[derive(Clone)]
pub struct DomainCache {
    by_host: Arc<RwLock<HashMap<String, Arc<Domain>>>>,
    primary: Arc<RwLock<Option<Arc<Domain>>>>,
}

impl DomainCache {
    pub fn new() -> Self {
        Self {
            by_host: Arc::new(RwLock::new(HashMap::new())),
            primary: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn load(&self, domains: Vec<Domain>) {
        let mut by_host = self.by_host.write().await;
        let mut primary = self.primary.write().await;

        by_host.clear();
        *primary = None;

        for domain in domains {
            let arc = Arc::new(domain);
            if arc.is_primary {
                *primary = Some(arc.clone());
            }
            by_host.insert(arc.host().to_string(), arc);
        }
    }

    pub async fn get(&self, host: &str) -> Option<Arc<Domain>> {
        let by_host = self.by_host.read().await;
        by_host.get(host).cloned()
    }

    pub async fn primary(&self) -> Option<Arc<Domain>> {
        let primary = self.primary.read().await;
        primary.clone()
    }

    pub async fn insert(&self, domain: Domain) {
        let arc = Arc::new(domain);
        let mut by_host = self.by_host.write().await;
        let mut primary = self.primary.write().await;

        if arc.is_primary {
            *primary = Some(arc.clone());
        }
        by_host.insert(arc.host().to_string(), arc);
    }

    pub async fn remove(&self, host: &str) {
        let mut by_host = self.by_host.write().await;
        let removed = by_host.remove(host);

        if let Some(domain) = removed
            && domain.is_primary
        {
            let mut primary = self.primary.write().await;
            *primary = None;
        }
    }

    pub async fn set_primary(&self, host: &str) {
        let by_host = self.by_host.read().await;
        if let Some(domain) = by_host.get(host).cloned() {
            drop(by_host);
            let mut primary = self.primary.write().await;
            *primary = Some(domain);
        }
    }

    pub async fn all(&self) -> Vec<Arc<Domain>> {
        let by_host = self.by_host.read().await;
        by_host.values().cloned().collect()
    }
}

impl Default for DomainCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_domain(url: &str, is_primary: bool) -> Domain {
        Domain {
            id: Uuid::new_v4().to_string(),
            url: url.to_string(),
            is_primary,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn host_strips_https() {
        let domain = make_domain("https://example.com", false);
        assert_eq!(domain.host(), "example.com");
    }

    #[test]
    fn host_strips_http() {
        let domain = make_domain("http://localhost:3000", false);
        assert_eq!(domain.host(), "localhost");
    }

    #[tokio::test]
    async fn load_and_get() {
        let cache = DomainCache::new();
        let domains = vec![
            make_domain("https://example.com", true),
            make_domain("https://other.com", false),
        ];
        cache.load(domains).await;

        let found = cache.get("example.com").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().url, "https://example.com");

        assert!(cache.get("other.com").await.is_some());

        let missing = cache.get("unknown.com").await;
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn primary_returns_primary_domain() {
        let cache = DomainCache::new();
        let domains = vec![
            make_domain("https://example.com", false),
            make_domain("https://primary.com", true),
        ];
        cache.load(domains).await;

        let primary = cache.primary().await;
        assert!(primary.is_some());
        assert_eq!(primary.unwrap().url, "https://primary.com");
    }

    #[tokio::test]
    async fn insert_and_remove() {
        let cache = DomainCache::new();
        let domain = make_domain("https://example.com", false);
        cache.insert(domain).await;

        assert!(cache.get("example.com").await.is_some());

        cache.remove("example.com").await;
        assert!(cache.get("example.com").await.is_none());
    }

    #[tokio::test]
    async fn set_primary_updates() {
        let cache = DomainCache::new();
        let domains = vec![
            make_domain("https://example.com", true),
            make_domain("https://other.com", false),
        ];
        cache.load(domains).await;

        // Initially example.com is primary
        assert_eq!(cache.primary().await.unwrap().url, "https://example.com");

        // Change primary to other.com
        cache.set_primary("other.com").await;
        assert_eq!(cache.primary().await.unwrap().url, "https://other.com");
    }
}
