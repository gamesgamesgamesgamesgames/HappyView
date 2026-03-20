use crate::plugin::host::{PluginState, register_host_functions};
use crate::plugin::memory::PluginResponse;
use crate::plugin::runtime::DEFAULT_FUEL;
use crate::plugin::{LoadedPlugin, PluginInfo, PluginSource};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use wasmtime::{Config, Engine, Linker, Module, Store};

const SUPPORTED_API_VERSION: &str = "1";

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("Failed to read plugin file: {0}")]
    ReadFile(#[from] std::io::Error),
    #[error("Failed to download plugin: {0}")]
    Download(#[from] reqwest::Error),
    #[error("SHA256 mismatch: expected {expected}, got {actual}")]
    Sha256Mismatch { expected: String, actual: String },
    #[error("Failed to parse plugin info: {0}")]
    ParseInfo(#[from] serde_json::Error),
    #[error("Plugin API version {0} not supported (requires {SUPPORTED_API_VERSION})")]
    UnsupportedApiVersion(String),
    #[error("Missing required secret: {0}")]
    MissingSecret(String),
    #[error("WASM validation failed: {0}")]
    WasmValidation(String),
}

/// Load a plugin from a file path
pub async fn load_from_file(path: &Path) -> Result<LoadedPlugin, LoadError> {
    let wasm_path = path.join("plugin.wasm");
    let wasm_bytes = tokio::fs::read(&wasm_path).await?;

    // Try to load plugin.toml for metadata override
    let toml_path = path.join("plugin.toml");
    let _toml_content = tokio::fs::read_to_string(&toml_path).await.ok();

    // Extract plugin info by instantiating WASM and calling plugin_info()
    // For now, create placeholder - full implementation needs wasmtime integration
    let info = extract_plugin_info(&wasm_bytes)?;

    validate_api_version(&info)?;

    Ok(LoadedPlugin {
        info,
        source: PluginSource::File {
            path: path.to_path_buf(),
        },
        wasm_bytes,
    })
}

/// Load a plugin from a URL
pub async fn load_from_url(
    client: &reqwest::Client,
    url: &str,
    expected_sha256: Option<&str>,
) -> Result<LoadedPlugin, LoadError> {
    let response = client.get(url).send().await?.error_for_status()?;
    let wasm_bytes = response.bytes().await?.to_vec();

    // Verify SHA256 if provided
    if let Some(expected) = expected_sha256 {
        let mut hasher = Sha256::new();
        hasher.update(&wasm_bytes);
        let actual = hex::encode(hasher.finalize());

        if actual != expected {
            return Err(LoadError::Sha256Mismatch {
                expected: expected.to_string(),
                actual,
            });
        }
    }

    let info = extract_plugin_info(&wasm_bytes)?;
    validate_api_version(&info)?;

    Ok(LoadedPlugin {
        info,
        source: PluginSource::Url {
            url: url.to_string(),
            sha256: expected_sha256.map(String::from),
        },
        wasm_bytes,
    })
}

/// Extract plugin info by instantiating WASM and calling plugin_info()
fn extract_plugin_info(wasm_bytes: &[u8]) -> Result<PluginInfo, LoadError> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            tokio::task::block_in_place(|| handle.block_on(extract_plugin_info_async(wasm_bytes)))
        }
        Err(_) => {
            let rt = tokio::runtime::Runtime::new().map_err(|e| {
                LoadError::WasmValidation(format!("failed to create runtime: {}", e))
            })?;
            rt.block_on(extract_plugin_info_async(wasm_bytes))
        }
    }
}

/// Async implementation of plugin info extraction via WASM instantiation
async fn extract_plugin_info_async(wasm_bytes: &[u8]) -> Result<PluginInfo, LoadError> {
    // Create async-enabled engine with fuel
    let mut config = Config::new();
    config.async_support(true);
    config.consume_fuel(true);
    let engine = Engine::new(&config).map_err(|e| LoadError::WasmValidation(e.to_string()))?;

    let module =
        Module::new(&engine, wasm_bytes).map_err(|e| LoadError::WasmValidation(e.to_string()))?;

    // Create linker with host functions
    let mut linker = Linker::new(&engine);
    register_host_functions(&mut linker).map_err(|e| LoadError::WasmValidation(e.to_string()))?;

    // Create minimal state - no db needed for plugin_info()
    let state = PluginState {
        plugin_id: "loading".into(),
        scope: "".into(),
        secrets: HashMap::new(),
        config: serde_json::Value::Null,
        db: None, // Not needed for plugin_info
        db_backend: crate::db::DatabaseBackend::Sqlite,
        http_client: reqwest::Client::new(),
        lexicons: std::sync::Arc::new(crate::lexicon::LexiconRegistry::new()),
        usage: Default::default(),
        memory: None,
        alloc: None,
        dealloc: None,
    };

    let mut store = Store::new(&engine, state);
    store
        .set_fuel(DEFAULT_FUEL)
        .map_err(|e| LoadError::WasmValidation(e.to_string()))?;

    // Instantiate
    let instance = linker
        .instantiate_async(&mut store, &module)
        .await
        .map_err(|e| LoadError::WasmValidation(format!("instantiation failed: {}", e)))?;

    // Get memory and alloc/dealloc
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| LoadError::WasmValidation("missing memory export".into()))?;
    let alloc = instance
        .get_typed_func::<u32, u32>(&mut store, "alloc")
        .map_err(|_| LoadError::WasmValidation("missing alloc export".into()))?;
    let dealloc = instance
        .get_typed_func::<(u32, u32), ()>(&mut store, "dealloc")
        .map_err(|_| LoadError::WasmValidation("missing dealloc export".into()))?;

    // Store in state
    store.data_mut().memory = Some(memory);
    store.data_mut().alloc = Some(alloc);
    store.data_mut().dealloc = Some(dealloc);

    // Call plugin_info
    let func = instance
        .get_typed_func::<(), i64>(&mut store, "plugin_info")
        .map_err(|_| LoadError::WasmValidation("missing plugin_info export".into()))?;

    let packed = func
        .call_async(&mut store, ())
        .await
        .map_err(|e| LoadError::WasmValidation(format!("plugin_info failed: {}", e)))?;

    // Unpack i64: upper 32 bits = ptr, lower 32 bits = len
    let ptr = (packed >> 32) as u32;
    let len = (packed & 0xFFFFFFFF) as u32;

    // Read result from memory
    let mem_data = memory.data(&store);
    if (ptr as usize) + (len as usize) > mem_data.len() {
        return Err(LoadError::WasmValidation(
            "plugin_info returned out of bounds pointer".into(),
        ));
    }
    let bytes = mem_data[ptr as usize..(ptr as usize + len as usize)].to_vec();

    // Parse response
    let response: PluginResponse<PluginInfo> = serde_json::from_slice(&bytes)?;

    response
        .into_result()
        .map_err(|e| LoadError::WasmValidation(format!("plugin error: {}", e.message)))
}

fn validate_api_version(info: &PluginInfo) -> Result<(), LoadError> {
    // Parse as integer for comparison
    let plugin_version: u32 = info.api_version.parse().unwrap_or(0);
    let supported_version: u32 = SUPPORTED_API_VERSION.parse().unwrap_or(1);

    if plugin_version > supported_version {
        return Err(LoadError::UnsupportedApiVersion(info.api_version.clone()));
    }

    Ok(())
}

/// Validate that all required secrets are present
pub fn validate_secrets(
    info: &PluginInfo,
    available_secrets: &std::collections::HashMap<String, String>,
) -> Result<(), LoadError> {
    for secret in &info.required_secrets {
        if !available_secrets.contains_key(secret) {
            return Err(LoadError::MissingSecret(secret.clone()));
        }
    }
    Ok(())
}

/// Parse PLUGIN_URLS environment variable
/// Format: id|url|sha256:hash,id|url|sha256:hash,...
pub fn parse_plugin_urls(env_value: &str) -> Vec<(String, String, Option<String>)> {
    env_value
        .split(',')
        .filter_map(|entry| {
            let parts: Vec<&str> = entry.trim().split('|').collect();
            if parts.len() >= 2 {
                let id = parts[0].to_string();
                let url = parts[1].to_string();
                let sha256 = parts
                    .get(2)
                    .and_then(|s| s.strip_prefix("sha256:").map(String::from));
                Some((id, url, sha256))
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_plugin_urls() {
        let input =
            "steam|https://example.com/steam.wasm|sha256:abc123,gog|https://example.com/gog.wasm";
        let result = parse_plugin_urls(input);

        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            (
                "steam".into(),
                "https://example.com/steam.wasm".into(),
                Some("abc123".into())
            )
        );
        assert_eq!(
            result[1],
            ("gog".into(), "https://example.com/gog.wasm".into(), None)
        );
    }

    #[test]
    fn test_validate_api_version() {
        let info = PluginInfo {
            id: "test".into(),
            name: "Test".into(),
            version: "1.0.0".into(),
            api_version: "1".into(),
            icon_url: None,
            required_secrets: vec![],
            config_schema: None,
        };

        assert!(validate_api_version(&info).is_ok());

        let future_info = PluginInfo {
            api_version: "99".into(),
            ..info
        };

        assert!(matches!(
            validate_api_version(&future_info),
            Err(LoadError::UnsupportedApiVersion(_))
        ));
    }
}
