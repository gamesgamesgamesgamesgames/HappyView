//! Integration tests for the plugin system
//!
//! Note: These tests require a valid WASM plugin to test against.
//! For now, we test the infrastructure without actual WASM execution.

use happyview::plugin::{LoadedPlugin, PluginInfo, PluginRegistry, PluginSource};

#[tokio::test]
async fn test_plugin_registry_crud() {
    let registry = PluginRegistry::new();

    // Create test plugin
    let plugin = LoadedPlugin {
        info: PluginInfo {
            id: "test-plugin".into(),
            name: "Test Plugin".into(),
            version: "1.0.0".into(),
            api_version: "1".into(),
            icon_url: None,
            required_secrets: vec![],
            auth_type: "oauth2".into(),
            config_schema: None,
        },
        source: PluginSource::File {
            path: "/tmp/test".into(),
        },
        wasm_bytes: vec![],
        manifest: None,
    };

    // Register
    registry.register(plugin).await;

    // Get
    let retrieved = registry.get("test-plugin").await;
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().info.name, "Test Plugin");

    // List
    let all = registry.list().await;
    assert_eq!(all.len(), 1);

    // Remove
    let removed = registry.remove("test-plugin").await;
    assert!(removed.is_some());

    // Verify removed
    assert!(registry.get("test-plugin").await.is_none());
}

#[tokio::test]
async fn test_plugin_registry_multiple() {
    let registry = PluginRegistry::new();

    for i in 0..5 {
        let plugin = LoadedPlugin {
            info: PluginInfo {
                id: format!("plugin-{}", i),
                name: format!("Plugin {}", i),
                version: "1.0.0".into(),
                api_version: "1".into(),
                icon_url: None,
                required_secrets: vec![],
                auth_type: "oauth2".into(),
                config_schema: None,
            },
            source: PluginSource::File {
                path: "/tmp/test".into(),
            },
            wasm_bytes: vec![],
            manifest: None,
        };
        registry.register(plugin).await;
    }

    assert_eq!(registry.list().await.len(), 5);
}
