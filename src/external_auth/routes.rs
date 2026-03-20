use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::Redirect,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::error::AppError;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/providers", get(list_providers))
        .route("/{plugin_id}/authorize", get(authorize))
        .route("/{plugin_id}/callback", get(callback))
        .route("/{plugin_id}/sync", post(sync))
        .route("/{plugin_id}/unlink", post(unlink))
}

#[derive(Serialize)]
struct ProviderInfo {
    id: String,
    name: String,
    icon_url: Option<String>,
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
        })
        .collect();

    Ok(Json(providers))
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    redirect_uri: String,
}

async fn authorize(
    State(state): State<AppState>,
    Path(plugin_id): Path<String>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let _plugin = state
        .plugin_registry
        .get(&plugin_id)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Plugin not found: {}", plugin_id)))?;

    // Generate state parameter for CSRF protection
    let state_param = uuid::Uuid::new_v4().to_string();

    // TODO: Store state in KV, call plugin's get_authorize_url()
    // For now, return placeholder
    let _ = query.redirect_uri;

    Ok(Json(serde_json::json!({
        "authorize_url": format!("https://example.com/oauth?state={}", state_param),
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
    State(_state): State<AppState>,
    Path(_plugin_id): Path<String>,
    Query(_query): Query<CallbackQuery>,
) -> Result<Redirect, AppError> {
    // TODO: Validate state, call plugin's handle_callback(), store tokens

    // For now, redirect to a placeholder
    Ok(Redirect::to("/"))
}

async fn sync(
    State(_state): State<AppState>,
    Path(_plugin_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    // TODO: Call plugin's sync_account(), process SyncRecords

    Ok(Json(serde_json::json!({
        "status": "ok",
        "synced": 0
    })))
}

async fn unlink(
    State(_state): State<AppState>,
    Path(_plugin_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    // TODO: Delete tokens, delete accountLink record

    Ok(Json(serde_json::json!({
        "status": "ok"
    })))
}
