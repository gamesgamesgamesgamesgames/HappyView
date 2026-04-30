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
#[serde(rename_all = "camelCase")]
pub struct ListDelegatesParams {
    pub account_did: String,
}

pub async fn list_delegates(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Query(params): Query<ListDelegatesParams>,
) -> Result<Response, AppError> {
    let claims = xrpc_claims
        .0
        .ok_or_else(|| AppError::Auth("listDelegates requires authentication".into()))?;

    super::verify_client_scope(&state, &claims, &params.account_did).await?;

    let caller_role = db::get_delegate_role(
        &state.db,
        state.db_backend,
        &params.account_did,
        claims.did(),
    )
    .await?
    .ok_or_else(|| AppError::Forbidden("you are not a delegate of this account".into()))?;

    if !caller_role.can_manage_members() {
        return Err(AppError::Forbidden(
            "only owners and admins can list delegates".into(),
        ));
    }

    let delegates = db::list_delegates(&state.db, state.db_backend, &params.account_did).await?;

    Ok(Json(json!({ "delegates": delegates })).into_response())
}
