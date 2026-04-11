use axum::extract::{DefaultBodyLimit, OriginalUri, State};
use axum::http::HeaderMap;
use axum::http::{Method, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use http_body_util::Full;
use std::convert::Infallible;
use std::net::IpAddr;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use crate::AppState;
use crate::admin;
use crate::auth::Claims;
use crate::error::AppError;
use crate::profile;
use crate::rate_limit::CheckResult;
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
        .route("/settings/logo", get(crate::admin::settings::serve_logo))
        .nest("/admin", admin::admin_routes(state.clone()))
        .nest("/auth", crate::auth::routes::routes())
        .nest("/external-auth", crate::external_auth::routes())
        // The ATProto OAuth spec allows either filename convention for the
        // client metadata document. We serve both so deployments can opt into
        // whichever URL their client_id points at.
        //
        // https://atproto.com/specs/oauth#types-of-clients
        .route("/oauth/client-metadata.json", get(client_metadata))
        .route("/oauth-client-metadata.json", get(client_metadata))
        .route("/xrpc/app.bsky.actor.getProfile", get(get_profile))
        .route(
            "/xrpc/com.atproto.repo.uploadBlob",
            post(repo::upload_blob).layer(DefaultBodyLimit::max(50 * 1024 * 1024)),
        )
        // Catch-all for dynamically registered lexicons
        .route("/xrpc/{method}", get(xrpc::xrpc_get).post(xrpc::xrpc_post))
        .route("/config", get(config_endpoint))
        .fallback_service(serve_dir)
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::AllowOrigin::mirror_request())
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::COOKIE])
                .allow_credentials(true),
        )
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn config_endpoint(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "public_url": state.config.public_url }))
}

async fn client_metadata(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Json<serde_json::Value> {
    let mut metadata = serde_json::to_value(&state.oauth.client_metadata).unwrap_or_default();

    // The `client_id` field in the response must exactly match the URL the
    // authorization server fetched. Construct it from the public URL + this
    // request's path so both `/oauth/client-metadata.json` and
    // `/oauth-client-metadata.json` work correctly.
    let client_id = format!(
        "{}{}",
        state.config.public_url.trim_end_matches('/'),
        uri.path()
    );
    metadata["client_id"] = serde_json::Value::String(client_id);

    let pool = &state.db;
    let backend = state.db_backend;

    if let Some(name) = crate::admin::settings::get_setting(pool, "app_name", backend).await {
        metadata["client_name"] = serde_json::Value::String(name);
    }

    if let Some(uri) = crate::admin::settings::get_setting(pool, "client_uri", backend).await {
        metadata["client_uri"] = serde_json::Value::String(uri);
    }

    // Logo: prefer uploaded logo_data (served at /settings/logo), fall back to logo_uri setting
    let has_logo_data = crate::admin::settings::get_setting(pool, "logo_data", backend)
        .await
        .is_some();
    if has_logo_data {
        metadata["logo_uri"] = serde_json::Value::String(format!(
            "{}/settings/logo",
            state.config.public_url.trim_end_matches('/')
        ));
    } else if let Some(uri) = crate::admin::settings::get_setting(pool, "logo_uri", backend).await {
        metadata["logo_uri"] = serde_json::Value::String(uri);
    }

    if let Some(uri) = crate::admin::settings::get_setting(pool, "tos_uri", backend).await {
        metadata["tos_uri"] = serde_json::Value::String(uri);
    }

    if let Some(uri) = crate::admin::settings::get_setting(pool, "policy_uri", backend).await {
        metadata["policy_uri"] = serde_json::Value::String(uri);
    }

    // OAuth scopes: override from the settings DB so admins can manage scopes without
    // restarting HappyView. The authorization server fetches this endpoint to validate
    // scope requests at PAR time, so this value is authoritative for non-loopback clients.
    if let Some(scopes) = crate::admin::settings::get_setting(pool, "oauth_scopes", backend).await {
        let normalized = scopes.split_whitespace().collect::<Vec<_>>().join(" ");
        if !normalized.is_empty() {
            metadata["scope"] = serde_json::Value::String(normalized);
        }
    }

    Json(metadata)
}

fn ip_from_forwarded_for(value: Option<&str>) -> Option<IpAddr> {
    let forwarded = value?;
    let first = forwarded.split(',').next()?;
    first.trim().parse::<IpAddr>().ok()
}

async fn get_profile(
    State(state): State<AppState>,
    claims: Claims,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let client_ip =
        ip_from_forwarded_for(headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()));
    let rate_key = claims.did().to_string();
    let check = state.rate_limiter.check(
        &rate_key,
        state.rate_limiter.default_cost_for_type("query"),
        client_ip,
    );

    if let CheckResult::Limited {
        retry_after,
        limit,
        reset,
    } = check
    {
        return Err(AppError::RateLimited {
            retry_after,
            limit,
            reset,
        });
    }

    let profile =
        profile::resolve_profile(&state.http, &state.config.plc_url, claims.did()).await?;
    let mut response = Json(profile).into_response();

    if let CheckResult::Allowed {
        remaining,
        limit,
        reset,
    } = check
    {
        let h = response.headers_mut();
        h.insert("RateLimit-Limit", limit.into());
        h.insert("RateLimit-Remaining", remaining.into());
        h.insert("RateLimit-Reset", reset.into());
    }

    Ok(response)
}
