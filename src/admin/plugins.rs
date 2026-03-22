use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;

use crate::AppState;
use crate::db::{adapt_sql, now_rfc3339};
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};
use crate::plugin::loader;

use super::auth::UserAuth;
use super::permissions::Permission;
use super::types::{AddPluginBody, PluginSummary};

/// GET /admin/plugins - list all loaded plugins
pub(super) async fn list(
    State(state): State<AppState>,
    auth: UserAuth,
) -> Result<Json<Vec<PluginSummary>>, AppError> {
    auth.require(Permission::SettingsManage).await?;

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

            PluginSummary {
                id: p.info.id.clone(),
                name: p.info.name.clone(),
                version: p.info.version.clone(),
                source,
                url,
                sha256,
                enabled: true, // Currently all loaded plugins are enabled
                auth_type: p.info.auth_type.clone(),
                required_secrets: p.info.required_secrets.clone(),
                loaded_at: None, // Would need to track this in registry
            }
        })
        .collect();

    Ok(Json(summaries))
}

/// POST /admin/plugins - add a new plugin from URL
pub(super) async fn add(
    State(state): State<AppState>,
    auth: UserAuth,
    Json(body): Json<AddPluginBody>,
) -> Result<Json<PluginSummary>, AppError> {
    auth.require(Permission::SettingsManage).await?;

    // Load plugin from URL
    let plugin = loader::load_from_url(&state.http, &body.url, body.sha256.as_deref())
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to load plugin: {}", e)))?;

    let summary = PluginSummary {
        id: plugin.info.id.clone(),
        name: plugin.info.name.clone(),
        version: plugin.info.version.clone(),
        source: "url".to_string(),
        url: Some(body.url.clone()),
        sha256: body.sha256.clone(),
        enabled: true,
        auth_type: plugin.info.auth_type.clone(),
        required_secrets: plugin.info.required_secrets.clone(),
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
    auth.require(Permission::SettingsManage).await?;

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
    auth.require(Permission::SettingsManage).await?;

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

    // Load fresh from URL
    let plugin = loader::load_from_url(&state.http, &url, sha256.as_deref())
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to reload plugin: {}", e)))?;

    let summary = PluginSummary {
        id: plugin.info.id.clone(),
        name: plugin.info.name.clone(),
        version: plugin.info.version.clone(),
        source: "url".to_string(),
        url: Some(url.clone()),
        sha256,
        enabled: true,
        auth_type: plugin.info.auth_type.clone(),
        required_secrets: plugin.info.required_secrets.clone(),
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
