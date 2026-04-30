use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::AppState;
use crate::auth::XrpcClaims;
use crate::error::AppError;

use super::db;

pub async fn list_accounts(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
) -> Result<Response, AppError> {
    let claims = xrpc_claims
        .0
        .ok_or_else(|| AppError::Auth("listAccounts requires authentication".into()))?;

    let caller_client_id = super::resolve_caller_client_id(&state, &claims).await?;

    let accounts =
        db::list_accounts_for_user(&state.db, state.db_backend, claims.did(), &caller_client_id)
            .await?;

    Ok(Json(json!({ "accounts": accounts })).into_response())
}
