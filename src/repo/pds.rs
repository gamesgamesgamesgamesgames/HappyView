use atrium_xrpc::{HttpClient, XrpcClient};
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use crate::AppState;
use crate::HappyViewOAuthSession;
use crate::error::AppError;

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

/// POST JSON to a PDS XRPC endpoint using the OAuth session.
/// The OAuthSession handles DPoP proof generation and nonce retry internally.
pub(crate) async fn pds_post_json_raw(
    _state: &AppState,
    session: &HappyViewOAuthSession,
    xrpc_method: &str,
    body: &Value,
) -> Result<reqwest::Response, AppError> {
    let pds_endpoint = session.base_uri();
    let url = format!("{}/xrpc/{xrpc_method}", pds_endpoint.trim_end_matches('/'));

    let body_bytes = serde_json::to_vec(body)
        .map_err(|e| AppError::Internal(format!("failed to serialize body: {e}")))?;

    let request = atrium_xrpc::http::Request::builder()
        .method("POST")
        .uri(&url)
        .header("content-type", "application/json")
        .body(body_bytes)
        .map_err(|e| AppError::Internal(format!("failed to build request: {e}")))?;

    let response = session
        .send_http(request)
        .await
        .map_err(|e| AppError::Internal(format!("PDS request failed: {e}")))?;

    // Convert atrium http::Response to reqwest::Response
    let (parts, body) = response.into_parts();
    let http_resp = atrium_xrpc::http::Response::from_parts(parts, body);
    let reqwest_resp = reqwest::Response::from(http_resp);

    Ok(reqwest_resp)
}

/// POST a binary blob to the PDS with OAuth session auth.
pub(super) async fn pds_post_blob(
    _state: &AppState,
    session: &HappyViewOAuthSession,
    content_type: &str,
    blob: Bytes,
) -> Result<Response, AppError> {
    let pds_endpoint = session.base_uri();
    let url = format!(
        "{}/xrpc/com.atproto.repo.uploadBlob",
        pds_endpoint.trim_end_matches('/')
    );

    let request = atrium_xrpc::http::Request::builder()
        .method("POST")
        .uri(&url)
        .header("content-type", content_type)
        .body(blob.to_vec())
        .map_err(|e| AppError::Internal(format!("failed to build request: {e}")))?;

    let response = session
        .send_http(request)
        .await
        .map_err(|e| AppError::Internal(format!("PDS uploadBlob failed: {e}")))?;

    let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
    let body_bytes = response.into_body();

    if status.is_success() {
        Ok((
            status,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            Bytes::from(body_bytes),
        )
            .into_response())
    } else {
        let body_str = String::from_utf8_lossy(&body_bytes);
        tracing::warn!(status = %status, body = %body_str, "PDS uploadBlob returned error");
        Err(AppError::PdsError(status, Bytes::from(body_bytes)))
    }
}
