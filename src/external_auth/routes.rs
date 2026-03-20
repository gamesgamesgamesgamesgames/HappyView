use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::Redirect,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::AppState;
use crate::auth::Claims;
use crate::error::AppError;
use crate::external_auth::{pds_write, state, tokens};
use crate::plugin::PluginExecutor;
use crate::plugin::sync::SyncProcessor;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/providers", get(list_providers))
        .route("/accounts", get(list_accounts))
        .route("/{plugin_id}/authorize", get(authorize))
        .route("/{plugin_id}/callback", get(callback))
        .route("/{plugin_id}/connect", post(connect_with_config))
        .route("/{plugin_id}/sync", post(sync))
        .route("/{plugin_id}/unlink", post(unlink))
}

#[derive(Serialize)]
struct ProviderInfo {
    id: String,
    name: String,
    icon_url: Option<String>,
    auth_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_schema: Option<serde_json::Value>,
}

async fn list_providers(
    State(state): State<AppState>,
) -> Result<Json<Vec<ProviderInfo>>, AppError> {
    let plugins = state.plugin_registry.list().await;

    let providers: Vec<ProviderInfo> = plugins
        .into_iter()
        .map(|p| ProviderInfo {
            id: p.info.id.clone(),
            name: p.info.name.clone(),
            icon_url: p.info.icon_url.clone(),
            auth_type: p.info.auth_type.clone(),
            config_schema: p.info.config_schema.clone(),
        })
        .collect();

    Ok(Json(providers))
}

async fn list_accounts(
    State(app_state): State<AppState>,
    claims: Claims,
) -> Result<Json<Vec<tokens::LinkedAccountSummary>>, AppError> {
    let accounts = tokens::list_linked_accounts(&app_state.db, app_state.db_backend, claims.did())
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(accounts))
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    redirect_uri: String,
}

async fn authorize(
    State(app_state): State<AppState>,
    Path(plugin_id): Path<String>,
    Query(query): Query<AuthorizeQuery>,
    claims: Claims,
) -> Result<Json<serde_json::Value>, AppError> {
    let _plugin = app_state
        .plugin_registry
        .get(&plugin_id)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Plugin not found: {}", plugin_id)))?;

    // Generate state parameter for CSRF protection
    let state_param = uuid::Uuid::new_v4().to_string();

    // Store state -> user mapping for callback validation
    state::store_state(
        &app_state.db,
        app_state.db_backend,
        &state_param,
        claims.did(),
        &plugin_id,
        &query.redirect_uri,
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    // Get plugin config (empty for now, could come from DB)
    let config = serde_json::Value::Null;

    // Load secrets from environment
    let secrets = load_plugin_secrets(&plugin_id);

    // Create executor and instance
    let executor = PluginExecutor::new(
        app_state.wasm_runtime.clone(),
        app_state.plugin_registry.clone(),
        app_state.db.clone(),
        app_state.db_backend,
        app_state.http.clone(),
        Arc::new(app_state.lexicons.clone()),
    );

    let mut instance = executor
        .instantiate(&plugin_id, &state_param, secrets, config.clone())
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let authorize_url = instance
        .call_get_authorize_url(&state_param, &query.redirect_uri, &config)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "authorize_url": authorize_url,
        "state": state_param
    })))
}

#[derive(Deserialize)]
#[allow(dead_code)] // Fields used when full OAuth flow is implemented
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn callback(
    State(app_state): State<AppState>,
    Path(plugin_id): Path<String>,
    Query(query): Query<CallbackQuery>,
) -> Result<Redirect, AppError> {
    // Validate required parameters
    let code = query.code.ok_or_else(|| {
        AppError::BadRequest(query.error.unwrap_or_else(|| "Missing code".into()))
    })?;
    let state_param = query
        .state
        .ok_or_else(|| AppError::BadRequest("Missing state".into()))?;

    // Validate state and get user DID + redirect_uri
    let stored_state = state::consume_state(&app_state.db, app_state.db_backend, &state_param)
        .await
        .map_err(|_| AppError::BadRequest("Invalid or expired state".into()))?;

    // Verify plugin_id matches
    if stored_state.plugin_id != plugin_id {
        return Err(AppError::BadRequest("Plugin ID mismatch".into()));
    }

    let config = serde_json::Value::Null;
    let secrets = load_plugin_secrets(&plugin_id);

    let executor = PluginExecutor::new(
        app_state.wasm_runtime.clone(),
        app_state.plugin_registry.clone(),
        app_state.db.clone(),
        app_state.db_backend,
        app_state.http.clone(),
        Arc::new(app_state.lexicons.clone()),
    );

    let mut instance = executor
        .instantiate(&plugin_id, &stored_state.did, secrets, config.clone())
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let token_set = instance
        .call_handle_callback(&code, &state_param, &config)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Get profile to get the account_id
    let profile = instance
        .call_get_profile(&token_set.access_token, &config)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Format expires_at as RFC3339 string
    let expires_at = token_set.expires_at.map(|dt| dt.to_rfc3339());

    // Store encrypted tokens
    tokens::store_tokens(
        &app_state.db,
        app_state.db_backend,
        app_state.config.token_encryption_key.as_ref(),
        &stored_state.did,
        &plugin_id,
        &profile.account_id,
        &token_set.access_token,
        token_set.refresh_token.as_deref(),
        Some(&token_set.token_type),
        None, // scope not in TokenSet
        expires_at.as_deref(),
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    // Redirect to the original redirect_uri
    Ok(Redirect::to(&stored_state.redirect_uri))
}

/// Connect with user-provided config (for API key auth type)
#[derive(Deserialize)]
struct ConnectConfigBody {
    /// User-provided configuration matching the plugin's config_schema
    config: serde_json::Value,
}

async fn connect_with_config(
    State(app_state): State<AppState>,
    Path(plugin_id): Path<String>,
    claims: Claims,
    Json(body): Json<ConnectConfigBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_did = claims.did();

    let plugin = app_state
        .plugin_registry
        .get(&plugin_id)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Plugin not found: {}", plugin_id)))?;

    // Verify this is an API key plugin
    if plugin.info.auth_type != "api_key" {
        return Err(AppError::BadRequest(
            "This endpoint is only for API key authentication".into(),
        ));
    }

    let secrets = load_plugin_secrets(&plugin_id);

    let executor = PluginExecutor::new(
        app_state.wasm_runtime.clone(),
        app_state.plugin_registry.clone(),
        app_state.db.clone(),
        app_state.db_backend,
        app_state.http.clone(),
        Arc::new(app_state.lexicons.clone()),
    );

    // For API key auth, we pass the user's config to handle_callback
    // The "code" is empty since there's no OAuth flow
    let mut instance = executor
        .instantiate(&plugin_id, user_did, secrets, body.config.clone())
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Call handle_callback with the config as the callback params
    // The plugin will extract the api_key from the config
    let token_set = instance
        .call_handle_callback("", "", &body.config)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Get profile to get the account_id
    let profile = instance
        .call_get_profile(&token_set.access_token, &body.config)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Format expires_at as RFC3339 string
    let expires_at = token_set.expires_at.map(|dt| dt.to_rfc3339());

    // Store encrypted tokens
    tokens::store_tokens(
        &app_state.db,
        app_state.db_backend,
        app_state.config.token_encryption_key.as_ref(),
        user_did,
        &plugin_id,
        &profile.account_id,
        &token_set.access_token,
        token_set.refresh_token.as_deref(),
        Some(&token_set.token_type),
        None,
        expires_at.as_deref(),
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "connected",
        "account_id": profile.account_id,
        "display_name": profile.display_name
    })))
}

async fn sync(
    State(app_state): State<AppState>,
    Path(plugin_id): Path<String>,
    claims: Claims,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_did = claims.did();

    let config = serde_json::Value::Null;
    let secrets = load_plugin_secrets(&plugin_id);

    let executor = PluginExecutor::new(
        app_state.wasm_runtime.clone(),
        app_state.plugin_registry.clone(),
        app_state.db.clone(),
        app_state.db_backend,
        app_state.http.clone(),
        Arc::new(app_state.lexicons.clone()),
    );

    let mut instance = executor
        .instantiate(&plugin_id, user_did, secrets, config.clone())
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Get decrypted access token from DB
    let stored = tokens::get_tokens(
        &app_state.db,
        app_state.db_backend,
        app_state.config.token_encryption_key.as_ref(),
        user_did,
        &plugin_id,
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let mut records = instance
        .call_sync_account(&stored.access_token, &config)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Resolve game references from database
    crate::plugin::sync::resolve_game_references(&app_state.db, app_state.db_backend, &mut records)
        .await;

    // Process records: sign those with sign=true
    let signer = app_state.attestation_signer.as_deref();
    let processor = SyncProcessor::new(signer, user_did.to_string());
    let processed = processor
        .process_records(records)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let processed_count = processed.len();

    // Write processed records to user's PDS
    let write_results = pds_write::write_records_to_pds(&app_state, user_did, processed).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "processed": processed_count,
        "written": write_results.len()
    })))
}

async fn unlink(
    State(app_state): State<AppState>,
    Path(plugin_id): Path<String>,
    claims: Claims,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_did = claims.did();

    // Delete tokens
    let deleted = tokens::delete_tokens(&app_state.db, app_state.db_backend, user_did, &plugin_id)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // TODO: Delete accountLink record from user's PDS

    Ok(Json(serde_json::json!({
        "status": "ok",
        "was_linked": deleted
    })))
}

fn load_plugin_secrets(plugin_id: &str) -> HashMap<String, String> {
    let prefix = format!("PLUGIN_{}_", plugin_id.to_uppercase());
    std::env::vars()
        .filter_map(|(k, v)| k.strip_prefix(&prefix).map(|name| (name.to_string(), v)))
        .collect()
}
