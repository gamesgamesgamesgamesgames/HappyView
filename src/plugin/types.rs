use serde::{Deserialize, Serialize};

/// A required secret with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretDefinition {
    /// Environment variable name (e.g., "PLUGIN_STEAM_API_KEY")
    pub key: String,
    /// Human-friendly name (e.g., "Steam Web API Key")
    pub name: String,
    /// Description of where to get the secret
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Plugin manifest loaded from manifest.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub api_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    #[serde(default)]
    pub required_secrets: Vec<SecretDefinition>,
    /// Authentication type: "oauth2", "openid", "api_key"
    #[serde(default = "default_auth_type")]
    pub auth_type: String,
    /// JSON Schema describing user-provided configuration (e.g., API keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_schema: Option<serde_json::Value>,
    /// Description of the plugin
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// WASM file name (relative to manifest location)
    #[serde(default = "default_wasm_file")]
    pub wasm_file: String,
}

fn default_wasm_file() -> String {
    "plugin.wasm".to_string()
}

/// Plugin metadata returned by plugin_info() - kept for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub api_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    #[serde(default)]
    pub required_secrets: Vec<String>,
    /// Authentication type: "oauth2", "openid", "api_key"
    #[serde(default = "default_auth_type")]
    pub auth_type: String,
    /// JSON Schema describing user-provided configuration (e.g., API keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_schema: Option<serde_json::Value>,
}

impl From<PluginManifest> for PluginInfo {
    fn from(manifest: PluginManifest) -> Self {
        PluginInfo {
            id: manifest.id,
            name: manifest.name,
            version: manifest.version,
            api_version: manifest.api_version,
            icon_url: manifest.icon_url,
            // Extract just the keys from SecretDefinition for PluginInfo
            required_secrets: manifest
                .required_secrets
                .into_iter()
                .map(|s| s.key)
                .collect(),
            auth_type: manifest.auth_type,
            config_schema: manifest.config_schema,
        }
    }
}

fn default_auth_type() -> String {
    "oauth2".to_string()
}

/// OAuth callback parameters passed to handle_callback()
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, String>,
}

/// Tokens returned by handle_callback() and refresh_tokens()
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub token_type: String,
}

/// Error returned by plugin functions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginError {
    pub code: PluginErrorCode,
    pub message: String,
    #[serde(default)]
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginErrorCode {
    UserDenied,
    InvalidToken,
    ServiceUnavailable,
    InvalidResponse,
    Unknown,
}

/// External profile returned by get_profile()
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalProfile {
    pub account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
}

/// Record returned by sync_account() - lexicon-aware
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRecord {
    pub collection: String,
    pub record: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dedup_key: Option<String>,
    /// Whether HappyView should add an attestation signature to this record
    #[serde(default)]
    pub sign: bool,
}

/// Strong reference to an AT Protocol record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrongRef {
    pub uri: String,
    pub cid: String,
}

/// Plugin source - file or URL
#[derive(Debug, Clone)]
pub enum PluginSource {
    File { path: std::path::PathBuf },
    Url { url: String, sha256: Option<String> },
}

/// Loaded plugin with runtime state
pub struct LoadedPlugin {
    pub info: PluginInfo,
    pub source: PluginSource,
    pub wasm_bytes: Vec<u8>,
    /// Full manifest if loaded from manifest.json (contains secret metadata)
    pub manifest: Option<PluginManifest>,
}
