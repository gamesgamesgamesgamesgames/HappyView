use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;

use crate::AppState;
use crate::auth::Claims;
use crate::error::AppError;

use super::pds::pds_post_blob;
use super::session::get_atp_session;

pub async fn upload_blob(
    State(state): State<AppState>,
    claims: Claims,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let session = get_atp_session(&state, claims.token()).await?;

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    pds_post_blob(&state, &session, content_type, body).await
}
