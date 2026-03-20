pub mod attestation;
pub mod encryption;
pub mod executor;
pub mod host;
pub mod loader;
pub mod memory;
mod runtime;
pub mod sync;
mod types;

pub use executor::{ExecutionError, PluginExecutor, PluginInstance};
pub use memory::{MemoryError, PluginEnvelopeError, PluginResponse};
pub use runtime::WasmRuntime;
pub use types::*;

use crate::db::{DatabaseBackend, adapt_sql, now_rfc3339};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Registry of loaded plugins
pub struct PluginRegistry {
    plugins: RwLock<HashMap<String, Arc<LoadedPlugin>>>,
    db: Option<sqlx::AnyPool>,
    db_backend: DatabaseBackend,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
            db: None,
            db_backend: DatabaseBackend::Sqlite,
        }
    }
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry backed by a database for persistence
    pub fn with_db(db: sqlx::AnyPool, db_backend: DatabaseBackend) -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
            db: Some(db),
            db_backend,
        }
    }

    pub async fn register(&self, plugin: LoadedPlugin) {
        let id = plugin.info.id.clone();

        // Persist to database if configured
        if let Some(db) = &self.db
            && let Err(e) = self.persist_plugin(db, &plugin).await
        {
            tracing::error!(plugin_id = %id, error = %e, "Failed to persist plugin to database");
        }

        self.plugins.write().await.insert(id, Arc::new(plugin));
    }

    async fn persist_plugin(
        &self,
        db: &sqlx::AnyPool,
        plugin: &LoadedPlugin,
    ) -> Result<(), sqlx::Error> {
        let (source, url, sha256) = match &plugin.source {
            PluginSource::File { path } => ("file", Some(path.display().to_string()), None),
            PluginSource::Url { url, sha256 } => ("url", Some(url.clone()), sha256.clone()),
        };

        let now = now_rfc3339();
        let sql = adapt_sql(
            "INSERT INTO plugins (id, source, url, sha256, enabled, loaded_at, api_version)
             VALUES (?, ?, ?, ?, 1, ?, ?)
             ON CONFLICT (id) DO UPDATE SET
                source = excluded.source,
                url = excluded.url,
                sha256 = excluded.sha256,
                loaded_at = excluded.loaded_at,
                api_version = excluded.api_version",
            self.db_backend,
        );

        sqlx::query(&sql)
            .bind(&plugin.info.id)
            .bind(source)
            .bind(url)
            .bind(sha256)
            .bind(&now)
            .bind(&plugin.info.api_version)
            .execute(db)
            .await?;

        Ok(())
    }

    pub async fn get(&self, id: &str) -> Option<Arc<LoadedPlugin>> {
        self.plugins.read().await.get(id).cloned()
    }

    pub async fn list(&self) -> Vec<Arc<LoadedPlugin>> {
        self.plugins.read().await.values().cloned().collect()
    }

    pub async fn remove(&self, id: &str) -> Option<Arc<LoadedPlugin>> {
        self.plugins.write().await.remove(id)
    }
}
