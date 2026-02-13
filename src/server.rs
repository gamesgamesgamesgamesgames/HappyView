use axum::extract::{DefaultBodyLimit, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::AppState;
use crate::admin;
use crate::auth::Claims;
use crate::error::AppError;
use crate::profile;
use crate::repo;
use crate::xrpc;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .nest("/admin", admin::admin_routes(state.clone()))
        .route("/xrpc/app.bsky.actor.getProfile", get(get_profile))
        .route(
            "/xrpc/com.atproto.repo.uploadBlob",
            post(repo::upload_blob).layer(DefaultBodyLimit::max(50 * 1024 * 1024)),
        )
        // Catch-all for dynamically registered lexicons
        .route("/xrpc/{method}", get(xrpc::xrpc_get).post(xrpc::xrpc_post))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn get_profile(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<Json<profile::Profile>, AppError> {
    let profile =
        profile::resolve_profile(&state.http, &state.config.plc_url, claims.did()).await?;
    Ok(Json(profile))
}
