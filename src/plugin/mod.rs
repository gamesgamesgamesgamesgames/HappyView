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

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Registry of loaded plugins
#[derive(Default)]
pub struct PluginRegistry {
    plugins: RwLock<HashMap<String, Arc<LoadedPlugin>>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(&self, plugin: LoadedPlugin) {
        let id = plugin.info.id.clone();
        self.plugins.write().await.insert(id, Arc::new(plugin));
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
