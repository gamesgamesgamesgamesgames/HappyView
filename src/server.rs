use axum::extract::{DefaultBodyLimit, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use http_body_util::Full;
use std::convert::Infallible;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use crate::AppState;
use crate::admin;
use crate::aip;
use crate::auth::Claims;
use crate::error::AppError;
use crate::profile;
use crate::repo;
use crate::xrpc;

pub fn router(state: AppState) -> Router {
    let static_dir = state.config.static_dir.clone();

    // SPA fallback: when ServeDir can't find a static file, check if the
    // parent path contains a _/index.html (Next.js dynamic route shell)
    // before falling back to the root index.html.
    let fallback_dir = static_dir.clone();
    let spa_fallback = tower::service_fn(move |req: axum::http::Request<_>| {
        let dir = fallback_dir.clone();
        async move {
            let path = req.uri().path();
            let segments: Vec<&str> = path.trim_matches('/').split('/').collect();

            // Try _/index.html in the parent directory (matches Next.js dynamic routes)
            if segments.len() >= 2 {
                let parent = segments[..segments.len() - 1].join("/");
                let dynamic_path = format!("{}/{}/_/index.html", dir, parent);
                if let Ok(body) = tokio::fs::read(&dynamic_path).await {
                    return Ok::<_, Infallible>(
                        axum::http::Response::builder()
                            .header("content-type", "text/html; charset=utf-8")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    );
                }
            }

            // Default: serve root index.html
            let index = format!("{}/index.html", dir);
            let body = tokio::fs::read(&index).await.unwrap_or_default();
            Ok::<_, Infallible>(
                axum::http::Response::builder()
                    .header("content-type", "text/html; charset=utf-8")
                    .body(Full::new(Bytes::from(body)))
                    .unwrap(),
            )
        }
    });

    let serve_dir = ServeDir::new(&static_dir).not_found_service(spa_fallback);

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
        .route("/config", get(config_endpoint))
        .route("/aip/{*path}", get(aip::aip_proxy).post(aip::aip_proxy))
        .fallback_service(serve_dir)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn config_endpoint(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "aip_url": state.config.aip_public_url }))
}

async fn get_profile(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<Json<profile::Profile>, AppError> {
    let profile =
        profile::resolve_profile(&state.http, &state.config.plc_url, claims.did()).await?;
    Ok(Json(profile))
}
