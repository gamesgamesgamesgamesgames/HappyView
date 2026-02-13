use axum::extract::{DefaultBodyLimit, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::auth::Claims;
use crate::error::AppError;
use crate::profile;
use crate::repo;
use crate::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/xrpc/app.bsky.actor.getProfile", get(get_profile))
        .route(
            "/xrpc/games.gamesgamesgamesgames.createGame",
            post(repo::create_game),
        )
        .route(
            "/xrpc/games.gamesgamesgamesgames.getGame",
            get(repo::get_game),
        )
        .route(
            "/xrpc/games.gamesgamesgamesgames.listGames",
            get(repo::list_games),
        )
        .route(
            "/xrpc/games.gamesgamesgamesgames.putGame",
            post(repo::put_game),
        )
        .route(
            "/xrpc/com.atproto.repo.uploadBlob",
            post(repo::upload_blob).layer(DefaultBodyLimit::max(50 * 1024 * 1024)),
        )
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
