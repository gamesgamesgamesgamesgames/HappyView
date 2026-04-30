use axum::Json;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;
use crate::auth::XrpcClaims;
use crate::error::AppError;

use super::db;

#[derive(Deserialize)]
pub struct GetAccountParams {
    pub did: String,
}

pub async fn get_account(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Query(params): Query<GetAccountParams>,
) -> Result<Response, AppError> {
    let claims = xrpc_claims
        .0
        .ok_or_else(|| AppError::Auth("getAccount requires authentication".into()))?;

    super::verify_client_scope(&state, &claims, &params.did).await?;

    let is_linked = db::is_account_linked(&state.db, state.db_backend, &params.did).await?;
    if !is_linked {
        return Err(AppError::NotFound("delegated account not found".into()));
    }

    let (linked_by, role, created_at) =
        db::get_account_for_user(&state.db, state.db_backend, &params.did, claims.did())
            .await?
            .ok_or_else(|| AppError::NotFound("you are not a delegate of this account".into()))?;

    Ok(Json(json!({
        "did": params.did,
        "role": role,
        "linkedBy": linked_by,
        "createdAt": created_at,
    }))
    .into_response())
}
