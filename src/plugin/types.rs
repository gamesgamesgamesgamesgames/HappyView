use serde::{Deserialize, Serialize};

/// Plugin metadata returned by plugin_info()
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_schema: Option<serde_json::Value>,
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
}
