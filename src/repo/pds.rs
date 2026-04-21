use std::sync::Arc;

use atrium_xrpc::{InputDataOrBytes, OutputDataOrBytes, XrpcClient, XrpcRequest, http::Method};
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use crate::AppState;
use crate::HappyViewOAuthSession;
use crate::error::AppError;

/// Abstraction over the two PDS authentication paths.
///
/// - `OAuth`: uses atrium's OAuthSession (dashboard cookie auth)
/// - `Dpop`: uses the manual DPoP session from `dpop_sessions` table (third-party apps)
#[derive(Clone)]
pub(crate) enum PdsAuth {
    OAuth(Arc<HappyViewOAuthSession>),
    Dpop {
        api_client_id: String,
        encryption_key: [u8; 32],
    },
}

impl PdsAuth {
    pub async fn post_json(
        &self,
        state: &AppState,
        user_did: &str,
        xrpc_method: &str,
        body: &Value,
    ) -> Result<reqwest::Response, AppError> {
        match self {
            PdsAuth::OAuth(session) => pds_post_json_raw(state, session, xrpc_method, body).await,
            PdsAuth::Dpop {
                api_client_id,
                encryption_key,
            } => {
                crate::oauth::pds_write::dpop_pds_post(
                    &state.http,
                    &state.db,
                    state.db_backend,
                    encryption_key,
                    &state.oauth,
                    &state.config.plc_url,
                    api_client_id,
                    user_did,
                    xrpc_method,
                    body,
                )
                .await
            }
        }
    }
}

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
/// Uses `send_xrpc` so the OAuthSession attaches DPoP proof and Bearer token.
pub(crate) async fn pds_post_json_raw(
    _state: &AppState,
    session: &HappyViewOAuthSession,
    xrpc_method: &str,
    body: &Value,
) -> Result<reqwest::Response, AppError> {
    let request = XrpcRequest {
        method: Method::POST,
        nsid: xrpc_method.to_string(),
        parameters: None::<()>,
        input: Some(InputDataOrBytes::Data(body.clone())),
        encoding: Some("application/json".to_string()),
    };

    let result: Result<OutputDataOrBytes<Value>, atrium_xrpc::Error<Value>> =
        session.send_xrpc(&request).await;

    match result {
        Ok(OutputDataOrBytes::Data(data)) => {
            let body_bytes = serde_json::to_vec(&data)
                .map_err(|e| AppError::Internal(format!("failed to serialize response: {e}")))?;
            let http_resp = atrium_xrpc::http::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(body_bytes)
                .map_err(|e| AppError::Internal(format!("failed to build response: {e}")))?;
            Ok(reqwest::Response::from(http_resp))
        }
        Ok(OutputDataOrBytes::Bytes(bytes)) => {
            let http_resp = atrium_xrpc::http::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(bytes)
                .map_err(|e| AppError::Internal(format!("failed to build response: {e}")))?;
            Ok(reqwest::Response::from(http_resp))
        }
        Err(e) => Err(AppError::Internal(format!("PDS request failed: {e}"))),
    }
}

/// POST a binary blob to the PDS with OAuth session auth.
pub(super) async fn pds_post_blob(
    _state: &AppState,
    session: &HappyViewOAuthSession,
    content_type: &str,
    blob: Bytes,
) -> Result<Response, AppError> {
    let request = XrpcRequest {
        method: Method::POST,
        nsid: "com.atproto.repo.uploadBlob".to_string(),
        parameters: None::<()>,
        input: Some(InputDataOrBytes::<()>::Bytes(blob.to_vec())),
        encoding: Some(content_type.to_string()),
    };

    let result: Result<OutputDataOrBytes<Value>, atrium_xrpc::Error<Value>> =
        session.send_xrpc(&request).await;

    match result {
        Ok(OutputDataOrBytes::Data(data)) => {
            let body_bytes = serde_json::to_vec(&data)
                .map_err(|e| AppError::Internal(format!("failed to serialize response: {e}")))?;
            Ok((
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                Bytes::from(body_bytes),
            )
                .into_response())
        }
        Ok(OutputDataOrBytes::Bytes(bytes)) => Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            Bytes::from(bytes),
        )
            .into_response()),
        Err(e) => Err(AppError::Internal(format!("PDS uploadBlob failed: {e}"))),
    }
}
