// tests/plugin_executor.rs

use happyview::db::DatabaseBackend;
use happyview::lexicon::LexiconRegistry;
use happyview::plugin::{
    ExecutionError, LoadedPlugin, PluginExecutor, PluginInfo, PluginRegistry, PluginSource,
    WasmRuntime,
};
use std::collections::HashMap;
use std::sync::Arc;

type Secrets = HashMap<String, String>;

async fn create_test_executor() -> (PluginExecutor, Arc<PluginRegistry>) {
    // Create in-memory database
    sqlx::any::install_default_drivers();
    let db = sqlx::AnyPool::connect("sqlite::memory:")
        .await
        .expect("Failed to create test database");

    let runtime = Arc::new(WasmRuntime::new().expect("Failed to create runtime"));
    let registry = Arc::new(PluginRegistry::new());
    let lexicons = Arc::new(LexiconRegistry::new());
    let http_client = reqwest::Client::new();

    let executor = PluginExecutor::new(
        runtime,
        registry.clone(),
        db,
        DatabaseBackend::Sqlite,
        http_client,
        lexicons,
    );

    (executor, registry)
}

fn load_test_plugin() -> LoadedPlugin {
    let wasm_bytes = std::fs::read(
        "tests/fixtures/test_plugin/target/wasm32-unknown-unknown/release/test_plugin.wasm",
    )
    .expect(
        "Test plugin not built. Run: cd tests/fixtures/test_plugin && cargo build --target wasm32-unknown-unknown --release",
    );

    LoadedPlugin {
        info: PluginInfo {
            id: "test".into(),
            name: "Test Plugin".into(),
            version: "1.0.0".into(),
            api_version: "1".into(),
            icon_url: None,
            required_secrets: vec![],
            auth_type: "oauth2".into(),
            config_schema: None,
        },
        source: PluginSource::File {
            path: "tests/fixtures/test_plugin".into(),
        },
        wasm_bytes,
        manifest: None,
    }
}

#[tokio::test]
async fn test_plugin_info() {
    let (executor, registry) = create_test_executor().await;
    let plugin = load_test_plugin();
    registry.register(plugin).await;

    let mut instance = executor
        .instantiate(
            "test",
            "user:did:plc:test",
            Secrets::new(),
            serde_json::Value::Null,
        )
        .await
        .expect("Failed to instantiate");

    let info = instance
        .call_plugin_info()
        .await
        .expect("Failed to get info");

    assert_eq!(info.id, "test");
    assert_eq!(info.name, "Test Plugin");
    assert_eq!(info.version, "1.0.0");
}

#[tokio::test]
async fn test_get_authorize_url() {
    let (executor, registry) = create_test_executor().await;
    let plugin = load_test_plugin();
    registry.register(plugin).await;

    let mut instance = executor
        .instantiate("test", "state:123", Secrets::new(), serde_json::Value::Null)
        .await
        .expect("Failed to instantiate");

    let url = instance
        .call_get_authorize_url(
            "state123",
            "https://app.example/callback",
            &serde_json::Value::Null,
        )
        .await
        .expect("Failed to get URL");

    assert!(url.starts_with("https://"));
}

#[tokio::test]
async fn test_handle_callback() {
    let (executor, registry) = create_test_executor().await;
    let plugin = load_test_plugin();
    registry.register(plugin).await;

    let mut instance = executor
        .instantiate(
            "test",
            "user:did:plc:test",
            Secrets::new(),
            serde_json::Value::Null,
        )
        .await
        .expect("Failed to instantiate");

    let mut params = HashMap::new();
    params.insert("code".to_string(), "code123".to_string());
    params.insert("state".to_string(), "state123".to_string());

    let tokens = instance
        .call_handle_callback(&params, &serde_json::Value::Null)
        .await
        .expect("Failed to handle callback");

    assert_eq!(tokens.access_token, "test-token");
    assert_eq!(tokens.token_type, "Bearer");
}

#[tokio::test]
async fn test_refresh_tokens() {
    let (executor, registry) = create_test_executor().await;
    let plugin = load_test_plugin();
    registry.register(plugin).await;

    let mut instance = executor
        .instantiate(
            "test",
            "user:did:plc:test",
            Secrets::new(),
            serde_json::Value::Null,
        )
        .await
        .expect("Failed to instantiate");

    let tokens = instance
        .call_refresh_tokens("old-refresh-token", &serde_json::Value::Null)
        .await
        .expect("Failed to refresh tokens");

    assert_eq!(tokens.access_token, "refreshed-token");
}

#[tokio::test]
async fn test_get_profile() {
    let (executor, registry) = create_test_executor().await;
    let plugin = load_test_plugin();
    registry.register(plugin).await;

    let mut instance = executor
        .instantiate(
            "test",
            "user:did:plc:test",
            Secrets::new(),
            serde_json::Value::Null,
        )
        .await
        .expect("Failed to instantiate");

    let profile = instance
        .call_get_profile("test-token", &serde_json::Value::Null)
        .await
        .expect("Failed to get profile");

    assert_eq!(profile.account_id, "12345");
    assert_eq!(profile.display_name, Some("Test User".into()));
}

#[tokio::test]
async fn test_sync_account() {
    let (executor, registry) = create_test_executor().await;
    let plugin = load_test_plugin();
    registry.register(plugin).await;

    let mut instance = executor
        .instantiate(
            "test",
            "user:did:plc:test",
            Secrets::new(),
            serde_json::Value::Null,
        )
        .await
        .expect("Failed to instantiate");

    let records = instance
        .call_sync_account("test-token", &serde_json::Value::Null)
        .await
        .expect("Failed to sync account");

    assert!(records.is_empty()); // Test plugin returns empty array
}

#[tokio::test]
async fn test_plugin_not_found() {
    let (executor, _registry) = create_test_executor().await;

    let result = executor
        .instantiate(
            "nonexistent",
            "scope",
            Secrets::new(),
            serde_json::Value::Null,
        )
        .await;

    assert!(matches!(result, Err(ExecutionError::PluginNotFound(_))));
}
