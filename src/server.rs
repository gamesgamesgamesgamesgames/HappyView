use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::auth::Claims;
use crate::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/xrpc/app.bsky.actor.getProfile", get(get_profile_placeholder))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

/// Placeholder authenticated endpoint to prove AIP integration works.
async fn get_profile_placeholder(
    State(_state): State<AppState>,
    claims: Claims,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "did": claims.did(),
        "message": "HappyView is alive! Replace this with a real implementation.",
    }))
}
