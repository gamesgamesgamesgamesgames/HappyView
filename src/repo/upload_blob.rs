use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use std::net::IpAddr;

use crate::AppState;
use crate::auth::Claims;
use crate::error::AppError;
use crate::rate_limit::CheckResult;

use super::pds::pds_post_blob;
use super::session::get_oauth_session;

pub async fn upload_blob(
    State(state): State<AppState>,
    claims: Claims,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let client_ip: Option<IpAddr> = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok());

    let rate_key = claims.did().to_string();
    let check = state.rate_limiter.check(
        &rate_key,
        state.rate_limiter.default_cost_for_type("procedure"),
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

    let session = get_oauth_session(&state, claims.did()).await?;

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    let mut response = pds_post_blob(&state, &session, content_type, body).await?;

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
