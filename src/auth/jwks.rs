use jsonwebtoken::jwk::JwkSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Periodically fetches and caches AIP's JWKS for token verification.
#[derive(Clone)]
pub struct JwksProvider {
    jwks: Arc<RwLock<Option<JwkSet>>>,
    jwks_url: String,
    http: reqwest::Client,
}

impl JwksProvider {
    pub fn new(jwks_url: String) -> Self {
        Self {
            jwks: Arc::new(RwLock::new(None)),
            jwks_url,
            http: reqwest::Client::new(),
        }
    }

    /// Fetch the JWKS from AIP once, returning an error if it fails.
    pub async fn refresh(&self) -> Result<(), String> {
        let resp = self
            .http
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| format!("failed to fetch JWKS: {e}"))?;

        let jwks: JwkSet = resp
            .json()
            .await
            .map_err(|e| format!("failed to parse JWKS: {e}"))?;

        info!(keys = jwks.keys.len(), "refreshed JWKS from AIP");
        *self.jwks.write().await = Some(jwks);
        Ok(())
    }

    /// Get a snapshot of the current keyset.
    pub async fn keyset(&self) -> Option<JwkSet> {
        self.jwks.read().await.clone()
    }

    /// Start a background task that refreshes JWKS every `interval`.
    pub fn spawn_refresh_loop(self, interval: std::time::Duration) {
        tokio::spawn(async move {
            loop {
                if let Err(e) = self.refresh().await {
                    warn!("JWKS refresh failed: {e}");
                }
                tokio::time::sleep(interval).await;
            }
        });
    }
}
