use crate::plugin::{LoadedPlugin, PluginInfo, PluginSource};
use sha2::{Digest, Sha256};
use std::path::Path;

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
    // TODO: Full implementation with wasmtime
    // For now, this is a placeholder that will be filled in when we integrate wasmtime calls

    // Validate it's valid WASM
    wasmtime::Module::validate(&wasmtime::Engine::default(), wasm_bytes)
        .map_err(|e| LoadError::WasmValidation(e.to_string()))?;

    // Return placeholder - real implementation calls plugin_info() export
    Ok(PluginInfo {
        id: "placeholder".into(),
        name: "Placeholder".into(),
        version: "0.0.0".into(),
        api_version: SUPPORTED_API_VERSION.into(),
        icon_url: None,
        required_secrets: vec![],
        config_schema: None,
    })
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
