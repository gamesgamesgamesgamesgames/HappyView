use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::collections::HashMap;

use crate::AppState;
use crate::db::{adapt_sql, now_rfc3339};
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};
use crate::plugin::encryption::{decrypt, encrypt};
use crate::plugin::loader;

use super::auth::UserAuth;
use super::permissions::Permission;
use super::types::{
    AddPluginBody, PluginPreviewResponse, PluginSecretsResponse, PluginSummary,
    PluginsListResponse, PreviewPluginBody, UpdatePluginSecretsBody,
};

/// GET /admin/plugins - list all loaded plugins
pub(super) async fn list(
    State(state): State<AppState>,
    auth: UserAuth,
) -> Result<Json<PluginsListResponse>, AppError> {
    auth.require(Permission::PluginsRead).await?;

    let plugins = state.plugin_registry.list().await;

    let summaries: Vec<PluginSummary> = plugins
        .into_iter()
        .map(|p| {
            let (source, url, sha256) = match &p.source {
                crate::plugin::PluginSource::File { path } => {
                    ("file".to_string(), Some(path.display().to_string()), None)
                }
                crate::plugin::PluginSource::Url { url, sha256 } => {
                    ("url".to_string(), Some(url.clone()), sha256.clone())
                }
            };

            // Use manifest for rich secret metadata if available, otherwise fallback to basic keys
            let required_secrets = if let Some(manifest) = &p.manifest {
                manifest
                    .required_secrets
                    .iter()
                    .map(|s| super::types::SecretDefinition {
                        key: s.key.clone(),
                        name: s.name.clone(),
                        description: s.description.clone(),
                    })
                    .collect()
            } else {
                // Legacy plugins without manifest - create minimal SecretDefinition from keys
                p.info
                    .required_secrets
                    .iter()
                    .map(|key| super::types::SecretDefinition {
                        key: key.clone(),
                        name: key.clone(), // Use key as name for legacy
                        description: None,
                    })
                    .collect()
            };

            PluginSummary {
                id: p.info.id.clone(),
                name: p.info.name.clone(),
                version: p.info.version.clone(),
                source,
                url,
                sha256,
                enabled: true, // Currently all loaded plugins are enabled
                auth_type: p.info.auth_type.clone(),
                required_secrets,
                loaded_at: None, // Would need to track this in registry
            }
        })
        .collect();

    Ok(Json(PluginsListResponse {
        plugins: summaries,
        encryption_configured: state.config.token_encryption_key.is_some(),
    }))
}

/// POST /admin/plugins/preview - preview a plugin from URL (fetches manifest only)
pub(super) async fn preview(
    State(state): State<AppState>,
    auth: UserAuth,
    Json(body): Json<PreviewPluginBody>,
) -> Result<Json<PluginPreviewResponse>, AppError> {
    auth.require(Permission::PluginsCreate).await?;

    let preview = loader::fetch_manifest(&state.http, &body.url)
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to fetch manifest: {}", e)))?;

    Ok(Json(PluginPreviewResponse {
        id: preview.manifest.id,
        name: preview.manifest.name,
        version: preview.manifest.version,
        description: preview.manifest.description,
        icon_url: preview.manifest.icon_url,
        auth_type: preview.manifest.auth_type,
        required_secrets: preview
            .manifest
            .required_secrets
            .into_iter()
            .map(|s| super::types::SecretDefinition {
                key: s.key,
                name: s.name,
                description: s.description,
            })
            .collect(),
        manifest_url: preview.manifest_url,
        wasm_url: preview.wasm_url,
    }))
}

/// POST /admin/plugins - add a new plugin from URL
pub(super) async fn add(
    State(state): State<AppState>,
    auth: UserAuth,
    Json(body): Json<AddPluginBody>,
) -> Result<Json<PluginSummary>, AppError> {
    auth.require(Permission::PluginsCreate).await?;

    // Load plugin via manifest (required)
    let preview = loader::fetch_manifest(&state.http, &body.url)
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to fetch manifest: {}", e)))?;

    let plugin = loader::load_from_manifest(&state.http, &preview, body.sha256.as_deref())
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to load plugin: {}", e)))?;

    // Use manifest for rich secret metadata if available
    let required_secrets = if let Some(manifest) = &plugin.manifest {
        manifest
            .required_secrets
            .iter()
            .map(|s| super::types::SecretDefinition {
                key: s.key.clone(),
                name: s.name.clone(),
                description: s.description.clone(),
            })
            .collect()
    } else {
        plugin
            .info
            .required_secrets
            .iter()
            .map(|key| super::types::SecretDefinition {
                key: key.clone(),
                name: key.clone(),
                description: None,
            })
            .collect()
    };

    let summary = PluginSummary {
        id: plugin.info.id.clone(),
        name: plugin.info.name.clone(),
        version: plugin.info.version.clone(),
        source: "url".to_string(),
        url: Some(body.url.clone()),
        sha256: body.sha256.clone(),
        enabled: true,
        auth_type: plugin.info.auth_type.clone(),
        required_secrets,
        loaded_at: Some(now_rfc3339()),
    };

    let plugin_id = plugin.info.id.clone();

    // Register the plugin (this also persists to DB)
    state.plugin_registry.register(plugin).await;

    log_event(
        &state.db,
        EventLog {
            event_type: "plugin.added".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(plugin_id),
            detail: serde_json::json!({ "url": body.url }),
        },
        state.db_backend,
    )
    .await;

    Ok(Json(summary))
}

/// DELETE /admin/plugins/{id} - remove a plugin
pub(super) async fn remove(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(plugin_id): Path<String>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::PluginsDelete).await?;

    // Remove from registry
    let removed = state.plugin_registry.remove(&plugin_id).await;

    if removed.is_none() {
        return Err(AppError::NotFound(format!(
            "Plugin '{}' not found",
            plugin_id
        )));
    }

    // Remove from database
    let sql = adapt_sql("DELETE FROM plugins WHERE id = ?", state.db_backend);
    sqlx::query(&sql)
        .bind(&plugin_id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to delete plugin: {}", e)))?;

    log_event(
        &state.db,
        EventLog {
            event_type: "plugin.removed".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(plugin_id),
            detail: serde_json::json!({}),
        },
        state.db_backend,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /admin/plugins/{id}/reload - reload a plugin from its source
pub(super) async fn reload(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(plugin_id): Path<String>,
) -> Result<Json<PluginSummary>, AppError> {
    auth.require(Permission::PluginsCreate).await?;

    // Get current plugin to find its source
    let current = state
        .plugin_registry
        .get(&plugin_id)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Plugin '{}' not found", plugin_id)))?;

    let (url, sha256) = match &current.source {
        crate::plugin::PluginSource::Url { url, sha256 } => (url.clone(), sha256.clone()),
        crate::plugin::PluginSource::File { .. } => {
            return Err(AppError::BadRequest(
                "Cannot reload file-based plugins via API".into(),
            ));
        }
    };

    // Remove old plugin
    state.plugin_registry.remove(&plugin_id).await;

    // Reload via manifest
    let preview = loader::fetch_manifest(&state.http, &url)
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to fetch manifest: {}", e)))?;

    let plugin = loader::load_from_manifest(&state.http, &preview, sha256.as_deref())
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to reload plugin: {}", e)))?;

    // Use manifest for rich secret metadata if available
    let required_secrets = if let Some(manifest) = &plugin.manifest {
        manifest
            .required_secrets
            .iter()
            .map(|s| super::types::SecretDefinition {
                key: s.key.clone(),
                name: s.name.clone(),
                description: s.description.clone(),
            })
            .collect()
    } else {
        plugin
            .info
            .required_secrets
            .iter()
            .map(|key| super::types::SecretDefinition {
                key: key.clone(),
                name: key.clone(),
                description: None,
            })
            .collect()
    };

    let summary = PluginSummary {
        id: plugin.info.id.clone(),
        name: plugin.info.name.clone(),
        version: plugin.info.version.clone(),
        source: "url".to_string(),
        url: Some(url.clone()),
        sha256,
        enabled: true,
        auth_type: plugin.info.auth_type.clone(),
        required_secrets,
        loaded_at: Some(now_rfc3339()),
    };

    // Register the reloaded plugin
    state.plugin_registry.register(plugin).await;

    log_event(
        &state.db,
        EventLog {
            event_type: "plugin.reloaded".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(plugin_id),
            detail: serde_json::json!({ "url": url }),
        },
        state.db_backend,
    )
    .await;

    Ok(Json(summary))
}

/// GET /admin/plugins/{id}/secrets - get plugin secrets (values masked)
pub(super) async fn get_secrets(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(plugin_id): Path<String>,
) -> Result<Json<PluginSecretsResponse>, AppError> {
    auth.require(Permission::PluginsRead).await?;

    let encryption_key = state
        .config
        .token_encryption_key
        .as_ref()
        .ok_or_else(|| AppError::Internal("Encryption key not configured".into()))?;

    // Verify plugin exists
    state
        .plugin_registry
        .get(&plugin_id)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Plugin '{}' not found", plugin_id)))?;

    // Get secrets from plugin_configs table
    let sql = adapt_sql(
        "SELECT config FROM plugin_configs WHERE plugin_id = ?",
        state.db_backend,
    );

    let row: Option<(String,)> = sqlx::query_as(&sql)
        .bind(&plugin_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch config: {}", e)))?;

    let secrets: HashMap<String, String> = match row {
        Some((config_json,)) => {
            let config: serde_json::Value = serde_json::from_str(&config_json)
                .map_err(|e| AppError::Internal(format!("Invalid config JSON: {}", e)))?;

            // Extract and decrypt secrets, then mask for display
            if let Some(secrets_obj) = config.get("secrets").and_then(|s| s.as_object()) {
                secrets_obj
                    .iter()
                    .filter_map(|(k, v)| {
                        v.as_str().and_then(|encrypted_b64| {
                            // Decode base64 and decrypt
                            let encrypted = BASE64.decode(encrypted_b64).ok()?;
                            let decrypted = decrypt(encryption_key, &encrypted).ok()?;
                            let val = String::from_utf8(decrypted).ok()?;

                            // Mask the value for display
                            let masked = if val.len() > 8 {
                                format!("********{}", &val[val.len() - 4..])
                            } else {
                                "********".to_string()
                            };
                            Some((k.clone(), masked))
                        })
                    })
                    .collect()
            } else {
                HashMap::new()
            }
        }
        None => HashMap::new(),
    };

    Ok(Json(PluginSecretsResponse { plugin_id, secrets }))
}

/// PUT /admin/plugins/{id}/secrets - update plugin secrets
pub(super) async fn update_secrets(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(plugin_id): Path<String>,
    Json(body): Json<UpdatePluginSecretsBody>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::PluginsCreate).await?;

    let encryption_key = state
        .config
        .token_encryption_key
        .as_ref()
        .ok_or_else(|| AppError::Internal("Encryption key not configured".into()))?;

    // Verify plugin exists
    state
        .plugin_registry
        .get(&plugin_id)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Plugin '{}' not found", plugin_id)))?;

    // Get existing config or create new one
    let sql = adapt_sql(
        "SELECT config FROM plugin_configs WHERE plugin_id = ?",
        state.db_backend,
    );

    let row: Option<(String,)> = sqlx::query_as(&sql)
        .bind(&plugin_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch config: {}", e)))?;

    let mut config: serde_json::Value = match row {
        Some((config_json,)) => serde_json::from_str(&config_json)
            .map_err(|e| AppError::Internal(format!("Invalid config JSON: {}", e)))?,
        None => serde_json::json!({}),
    };

    // Get existing encrypted secrets to preserve unchanged values
    let existing_secrets: HashMap<String, String> = config
        .get("secrets")
        .and_then(|s| s.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    // Merge secrets: if new value starts with "********", keep existing encrypted value
    // Otherwise, encrypt the new value
    let mut merged_secrets = serde_json::Map::new();
    for (key, value) in body.secrets {
        if value.starts_with("********") {
            // Keep existing encrypted value if present
            if let Some(existing) = existing_secrets.get(&key) {
                merged_secrets.insert(key, serde_json::Value::String(existing.clone()));
            }
        } else if !value.is_empty() {
            // Encrypt new value and store as base64
            let encrypted = encrypt(encryption_key, value.as_bytes())
                .map_err(|e| AppError::Internal(format!("Encryption failed: {}", e)))?;
            let encoded = BASE64.encode(&encrypted);
            merged_secrets.insert(key, serde_json::Value::String(encoded));
        }
        // Empty values are not stored (allows clearing a secret)
    }

    // Update config with merged secrets
    config["secrets"] = serde_json::Value::Object(merged_secrets);

    let config_json = serde_json::to_string(&config)
        .map_err(|e| AppError::Internal(format!("Failed to serialize config: {}", e)))?;

    // Upsert into plugin_configs
    let sql = adapt_sql(
        "INSERT INTO plugin_configs (plugin_id, config, updated_at) VALUES (?, ?, ?)
         ON CONFLICT (plugin_id) DO UPDATE SET config = EXCLUDED.config, updated_at = EXCLUDED.updated_at",
        state.db_backend,
    );

    sqlx::query(&sql)
        .bind(&plugin_id)
        .bind(&config_json)
        .bind(now_rfc3339())
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to update secrets: {}", e)))?;

    log_event(
        &state.db,
        EventLog {
            event_type: "plugin.secrets_updated".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(plugin_id),
            detail: serde_json::json!({}),
        },
        state.db_backend,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}
