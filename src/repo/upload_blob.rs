use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;

use crate::AppState;
use crate::auth::XrpcClaims;
use crate::error::AppError;
use crate::rate_limit::CheckResult;

use super::pds::pds_post_blob;
use super::session::get_oauth_session;

pub async fn upload_blob(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let claims = xrpc_claims
        .0
        .ok_or_else(|| AppError::Auth("uploadBlob requires DPoP authentication".into()))?;
    let check = if let Some(client_key) = claims.client_key() {
        let cost = state
            .rate_limiter
            .default_cost_for_type(client_key, "procedure");
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

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    let mut response = if let Some(client_key) = claims.client_key() {
        let encryption_key = state
            .config
            .token_encryption_key
            .as_ref()
            .ok_or_else(|| AppError::Internal("TOKEN_ENCRYPTION_KEY not configured".into()))?;

        let api_client_id = crate::repo::get_dpop_client_id(&state, client_key).await?;

        let resp = crate::oauth::pds_write::dpop_pds_post_blob(
            &state.http,
            &state.db,
            state.db_backend,
            encryption_key,
            &state.config.plc_url,
            &api_client_id,
            claims.did(),
            content_type,
            body,
        )
        .await?;

        crate::repo::forward_pds_response(resp).await?
    } else {
        let session = get_oauth_session(&state, claims.did()).await?;
        pds_post_blob(&state, &session, content_type, body).await?
    };

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
