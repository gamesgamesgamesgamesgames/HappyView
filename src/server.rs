use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::auth::Claims;
use crate::error::AppError;
use crate::profile;
use crate::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/xrpc/app.bsky.actor.getProfile", get(get_profile))
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
    let profile = profile::resolve_profile(&state.http, claims.did()).await?;
    Ok(Json(profile))
}
