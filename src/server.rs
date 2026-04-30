use axum::extract::{DefaultBodyLimit, State};
use axum::http::{Method, header};
use axum::response::{IntoResponse, Response};
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
use crate::auth::XrpcClaims;
use crate::domain_middleware::resolve_domain;
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

    let domain_routes = Router::new()
        .merge(crate::spaces::routes::space_routes())
        .nest("/auth", crate::auth::routes::routes())
        .nest("/external-auth", crate::external_auth::routes())
        .nest("/oauth", crate::oauth::routes::routes())
        // https://atproto.com/specs/oauth#types-of-clients
        .route("/oauth-client-metadata.json", get(client_metadata))
        .route("/xrpc/app.bsky.actor.getProfile", get(get_profile))
        .route(
            "/xrpc/com.atproto.repo.uploadBlob",
            post(repo::upload_blob).layer(DefaultBodyLimit::max(50 * 1024 * 1024)),
        )
        .route(
            "/xrpc/dev.happyview.listApiClients",
            get(crate::dev_happyview::list_api_clients),
        )
        .route(
            "/xrpc/dev.happyview.getApiClient",
            get(crate::dev_happyview::get_api_client),
        )
        .route(
            "/xrpc/dev.happyview.createApiClient",
            post(crate::dev_happyview::create_api_client),
        )
        .route(
            "/xrpc/dev.happyview.deleteApiClient",
            post(crate::dev_happyview::delete_api_client),
        )
        // Delegation
        .route(
            "/xrpc/dev.happyview.delegation.linkAccount",
            post(crate::delegation::link_account::link_account),
        )
        .route(
            "/xrpc/dev.happyview.delegation.unlinkAccount",
            post(crate::delegation::unlink_account::unlink_account),
        )
        .route(
            "/xrpc/dev.happyview.delegation.addDelegate",
            post(crate::delegation::add_delegate::add_delegate),
        )
        .route(
            "/xrpc/dev.happyview.delegation.removeDelegate",
            post(crate::delegation::remove_delegate::remove_delegate),
        )
        .route(
            "/xrpc/dev.happyview.delegation.listAccounts",
            get(crate::delegation::list_accounts::list_accounts),
        )
        .route(
            "/xrpc/dev.happyview.delegation.getAccount",
            get(crate::delegation::get_account::get_account),
        )
        .route(
            "/xrpc/dev.happyview.delegation.listDelegates",
            get(crate::delegation::list_delegates::list_delegates),
        )
        // Catch-all for dynamically registered lexicons
        .route("/xrpc/{method}", get(xrpc::xrpc_get).post(xrpc::xrpc_post))
        .route("/config", get(config_endpoint))
        .route("/settings/logo", get(crate::admin::settings::serve_logo))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            resolve_domain,
        ));

    Router::new()
        .route("/health", get(health))
        .nest("/admin", admin::admin_routes(state.clone()))
        .merge(domain_routes)
        .fallback_service(serve_dir)
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::AllowOrigin::mirror_request())
                .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
                .allow_headers([
                    header::CONTENT_TYPE,
                    header::AUTHORIZATION,
                    header::COOKIE,
                    axum::http::HeaderName::from_static("x-client-key"),
                    axum::http::HeaderName::from_static("x-client-secret"),
                    axum::http::HeaderName::from_static("dpop"),
                    axum::http::HeaderName::from_static("atproto-accept-labelers"),
                    axum::http::HeaderName::from_static("atproto-proxy"),
                ])
                .allow_credentials(true),
        )
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn config_endpoint(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Json<serde_json::Value> {
    let domain_url = crate::domain_middleware::extract_domain(&req)
        .map(|d| d.url.clone())
        .unwrap_or_else(|| state.config.public_url.clone());

    let pool = &state.db;
    let backend = state.db_backend;

    let app_name = crate::admin::settings::get_setting(pool, "app_name", backend)
        .await
        .or_else(|| state.config.app_name.clone());

    let has_logo_data = crate::admin::settings::get_setting(pool, "logo_data", backend)
        .await
        .is_some();
    let logo_url = if has_logo_data {
        Some(format!(
            "{}/settings/logo",
            domain_url.trim_end_matches('/')
        ))
    } else {
        crate::admin::settings::get_setting(pool, "logo_uri", backend)
            .await
            .or_else(|| state.config.logo_uri.clone())
    };

    let version: &str = match option_env!("HAPPYVIEW_VERSION") {
        Some(v) if !v.is_empty() => v.trim_start_matches('v'),
        _ => env!("CARGO_PKG_VERSION"),
    };

    Json(serde_json::json!({
        "public_url": domain_url,
        "version": version,
        "database_backend": format!("{:?}", state.config.database_backend).to_lowercase(),
        "jetstream_url": state.config.jetstream_url,
        "relay_url": state.config.relay_url,
        "plc_url": state.config.plc_url,
        "default_rate_limit_capacity": state.config.default_rate_limit_capacity,
        "default_rate_limit_refill_rate": state.config.default_rate_limit_refill_rate,
        "app_name": app_name,
        "logo_url": logo_url,
    }))
}

async fn client_metadata(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Json<serde_json::Value> {
    let domain_url = crate::domain_middleware::extract_domain(&req)
        .map(|d| d.url.clone())
        .unwrap_or_else(|| state.config.public_url.clone());

    let oauth_client = state.oauth.get_for_domain(&domain_url);
    let mut metadata = serde_json::to_value(&oauth_client.client_metadata).unwrap_or_default();

    // The `client_id` field in the response must exactly match the URL the
    // authorization server fetched.
    let client_id = format!(
        "{}/oauth-client-metadata.json",
        domain_url.trim_end_matches('/')
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
            domain_url.trim_end_matches('/')
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

    Json(metadata)
}

async fn get_profile(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
) -> Result<Response, AppError> {
    let claims = xrpc_claims
        .0
        .ok_or_else(|| AppError::Auth("getProfile requires DPoP authentication".into()))?;
    let check = if let Some(client_key) = claims.client_key() {
        let cost = state
            .rate_limiter
            .default_cost_for_type(client_key, "query");
        Some(state.rate_limiter.check(client_key, cost))
    } else {
        None
    };

    if let Some(CheckResult::Limited {
        retry_after,
        limit,
        reset,
    }) = check
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

    if let Some(CheckResult::Allowed {
        remaining,
        limit,
        reset,
    }) = check
    {
        let h = response.headers_mut();
        h.insert("RateLimit-Limit", limit.into());
        h.insert("RateLimit-Remaining", remaining.into());
        h.insert("RateLimit-Reset", reset.into());
    }

    Ok(response)
}
