use crate::plugin::{LoadedPlugin, PluginInfo, PluginManifest, PluginSource};
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
    #[error("Manifest not found at {0}")]
    ManifestNotFound(String),
}

/// Preview result with manifest and derived WASM URL
#[derive(Debug, Clone, serde::Serialize)]
pub struct PluginPreview {
    pub manifest: PluginManifest,
    pub manifest_url: String,
    pub wasm_url: String,
}

/// Fetch plugin manifest from a URL (or derive manifest URL from WASM URL)
pub async fn fetch_manifest(
    client: &reqwest::Client,
    url: &str,
) -> Result<PluginPreview, LoadError> {
    // If URL ends with .wasm, derive manifest URL from same directory
    let (manifest_url, base_url) = if url.ends_with(".wasm") {
        let base = url.rsplit_once('/').map(|(b, _)| b).unwrap_or("");
        (format!("{}/manifest.json", base), base.to_string())
    } else if url.ends_with("manifest.json") {
        let base = url.rsplit_once('/').map(|(b, _)| b).unwrap_or("");
        (url.to_string(), base.to_string())
    } else {
        // Assume it's a base directory URL
        (
            format!("{}/manifest.json", url.trim_end_matches('/')),
            url.trim_end_matches('/').to_string(),
        )
    };

    let response = client
        .get(&manifest_url)
        .send()
        .await?
        .error_for_status()
        .map_err(|_| LoadError::ManifestNotFound(manifest_url.clone()))?;

    let manifest: PluginManifest = response.json().await?;

    // Derive WASM URL from manifest
    let wasm_url = format!("{}/{}", base_url, manifest.wasm_file);

    Ok(PluginPreview {
        manifest,
        manifest_url,
        wasm_url,
    })
}

/// Load a plugin from a manifest (fetches WASM separately)
pub async fn load_from_manifest(
    client: &reqwest::Client,
    preview: &PluginPreview,
    expected_sha256: Option<&str>,
) -> Result<LoadedPlugin, LoadError> {
    let response = client
        .get(&preview.wasm_url)
        .send()
        .await?
        .error_for_status()?;
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

    let info: PluginInfo = preview.manifest.clone().into();
    validate_api_version(&info)?;

    Ok(LoadedPlugin {
        info,
        source: PluginSource::Url {
            url: preview.wasm_url.clone(),
            sha256: expected_sha256.map(String::from),
        },
        wasm_bytes,
        manifest: Some(preview.manifest.clone()),
    })
}

/// Load a plugin from a local directory (requires manifest.json)
pub async fn load_from_file(path: &Path) -> Result<LoadedPlugin, LoadError> {
    // Load manifest.json
    let manifest_path = path.join("manifest.json");
    let manifest_content = tokio::fs::read_to_string(&manifest_path)
        .await
        .map_err(|_| LoadError::ManifestNotFound(manifest_path.display().to_string()))?;

    let manifest: PluginManifest = serde_json::from_str(&manifest_content)?;

    // Load WASM file specified in manifest
    let wasm_path = path.join(&manifest.wasm_file);
    let wasm_bytes = tokio::fs::read(&wasm_path).await?;

    let info: PluginInfo = manifest.clone().into();
    validate_api_version(&info)?;

    Ok(LoadedPlugin {
        info,
        source: PluginSource::File {
            path: path.to_path_buf(),
        },
        wasm_bytes,
        manifest: Some(manifest),
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
            auth_type: "oauth2".into(),
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
