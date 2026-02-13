use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use crate::AppState;
use crate::error::AppError;

use super::dpop::generate_dpop_proof;
use super::session::AtpSession;

/// Forward a PDS response back to the client, preserving status and body.
pub(crate) async fn forward_pds_response(resp: reqwest::Response) -> Result<Response, AppError> {
    let status = resp.status();
    let body = resp
        .bytes()
        .await
        .map_err(|e| AppError::Internal(format!("failed to read PDS response: {e}")))?;

    let axum_status = StatusCode::from_u16(status.as_u16()).unwrap();

    if status.is_success() {
        Ok((
            axum_status,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response())
    } else {
        let body_str = String::from_utf8_lossy(&body);
        tracing::warn!(status = %axum_status, body = %body_str, "PDS returned error");
        Err(AppError::PdsError(axum_status, body))
    }
}

/// POST JSON to a PDS XRPC endpoint with DPoP auth and nonce retry.
/// Returns the raw reqwest::Response so callers can inspect the body.
pub(crate) async fn pds_post_json_raw(
    state: &AppState,
    session: &AtpSession,
    xrpc_method: &str,
    body: &Value,
) -> Result<reqwest::Response, AppError> {
    let url = format!(
        "{}/xrpc/{xrpc_method}",
        session.pds_endpoint.trim_end_matches('/')
    );

    let dpop = generate_dpop_proof("POST", &url, &session.dpop_jwk, &session.access_token, None)?;

    let resp = state
        .http
        .post(&url)
        .header("authorization", format!("DPoP {}", session.access_token))
        .header("dpop", &dpop)
        .json(body)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("PDS request failed: {e}")))?;

    // Retry with nonce if PDS requires it
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED
        && let Some(nonce) = resp
            .headers()
            .get("dpop-nonce")
            .and_then(|v| v.to_str().ok())
    {
        let nonce = nonce.to_string();
        tracing::debug!("retrying with DPoP nonce");

        let dpop = generate_dpop_proof(
            "POST",
            &url,
            &session.dpop_jwk,
            &session.access_token,
            Some(&nonce),
        )?;

        let resp = state
            .http
            .post(&url)
            .header("authorization", format!("DPoP {}", session.access_token))
            .header("dpop", &dpop)
            .json(body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("PDS request retry failed: {e}")))?;

        return Ok(resp);
    }

    Ok(resp)
}

/// POST a binary blob to the PDS with DPoP auth and nonce retry.
pub(super) async fn pds_post_blob(
    state: &AppState,
    session: &AtpSession,
    content_type: &str,
    blob: Bytes,
) -> Result<Response, AppError> {
    let url = format!(
        "{}/xrpc/com.atproto.repo.uploadBlob",
        session.pds_endpoint.trim_end_matches('/')
    );

    let dpop = generate_dpop_proof("POST", &url, &session.dpop_jwk, &session.access_token, None)?;

    let resp = state
        .http
        .post(&url)
        .header("authorization", format!("DPoP {}", session.access_token))
        .header("dpop", &dpop)
        .header("content-type", content_type)
        .body(blob.clone())
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("PDS uploadBlob failed: {e}")))?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED
        && let Some(nonce) = resp
            .headers()
            .get("dpop-nonce")
            .and_then(|v| v.to_str().ok())
    {
        let nonce = nonce.to_string();
        tracing::debug!("retrying uploadBlob with DPoP nonce");

        let dpop = generate_dpop_proof(
            "POST",
            &url,
            &session.dpop_jwk,
            &session.access_token,
            Some(&nonce),
        )?;

        let resp = state
            .http
            .post(&url)
            .header("authorization", format!("DPoP {}", session.access_token))
            .header("dpop", &dpop)
            .header("content-type", content_type)
            .body(blob)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("PDS uploadBlob retry failed: {e}")))?;

        return forward_pds_response(resp).await;
    }

    forward_pds_response(resp).await
}
