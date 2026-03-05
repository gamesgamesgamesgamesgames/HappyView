mod procedure;
mod query;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use std::collections::HashMap;

use crate::AppState;
use crate::auth::Claims;
use crate::error::AppError;
use crate::lexicon::LexiconType;
use crate::resolve::resolve_nsid_authority;

/// Proxy an unrecognized XRPC method to its home AppView resolved via DNS.
async fn proxy_to_authority(
    state: &AppState,
    method: &str,
    query_string: &str,
    body: Option<&serde_json::Value>,
) -> Result<Response, AppError> {
    let (_did, pds_endpoint) = resolve_nsid_authority(&state.http, &state.config.plc_url, method)
        .await
        .map_err(|e| {
            AppError::BadGateway(format!("failed to resolve authority for {method}: {e}"))
        })?;

    let mut url = format!("{}/xrpc/{method}", pds_endpoint.trim_end_matches('/'),);
    if !query_string.is_empty() {
        url.push('?');
        url.push_str(query_string);
    }

    let request = if let Some(json_body) = body {
        state.http.post(&url).json(json_body)
    } else {
        state.http.get(&url)
    };

    let upstream = request
        .send()
        .await
        .map_err(|e| AppError::BadGateway(format!("upstream request failed for {method}: {e}")))?;

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    let bytes = upstream.bytes().await.map_err(|e| {
        AppError::BadGateway(format!(
            "failed to read upstream response for {method}: {e}"
        ))
    })?;

    if !status.is_success() {
        return Err(AppError::PdsError(status, bytes));
    }

    Ok(Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Body::from(bytes))
        .unwrap())
}

/// Catch-all GET handler for XRPC queries.
pub async fn xrpc_get(
    State(state): State<AppState>,
    Path(method): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let lexicon = match state.lexicons.get(&method).await {
        Some(l) => l,
        None => {
            let query_string: String = params
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            return proxy_to_authority(&state, &method, &query_string, None).await;
        }
    };

    if lexicon.lexicon_type != LexiconType::Query {
        return Err(AppError::BadRequest(format!(
            "{method} is not a query endpoint"
        )));
    }

    query::handle_query(&state, &method, &params, &lexicon).await
}

/// Catch-all POST handler for XRPC procedures.
pub async fn xrpc_post(
    State(state): State<AppState>,
    Path(method): Path<String>,
    claims: Claims,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, AppError> {
    let lexicon = match state.lexicons.get(&method).await {
        Some(l) => l,
        None => return proxy_to_authority(&state, &method, "", Some(&body)).await,
    };

    if lexicon.lexicon_type != LexiconType::Procedure {
        return Err(AppError::BadRequest(format!(
            "{method} is not a procedure endpoint"
        )));
    }

    procedure::handle_procedure(&state, &method, &claims, &body, &lexicon).await
}
