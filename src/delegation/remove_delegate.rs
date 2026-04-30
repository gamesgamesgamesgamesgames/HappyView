use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;
use crate::auth::XrpcClaims;
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};

use super::DelegateRole;
use super::db;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveDelegateInput {
    pub account_did: String,
    pub user_did: String,
}

pub async fn remove_delegate(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Json(input): Json<RemoveDelegateInput>,
) -> Result<Response, AppError> {
    let claims = xrpc_claims
        .0
        .ok_or_else(|| AppError::Auth("removeDelegate requires authentication".into()))?;

    let caller_did = claims.did().to_string();

    super::verify_client_scope(&state, &claims, &input.account_did).await?;

    let caller_role =
        db::get_delegate_role(&state.db, state.db_backend, &input.account_did, &caller_did)
            .await?
            .ok_or_else(|| AppError::Forbidden("you are not a delegate of this account".into()))?;

    if !caller_role.can_manage_members() {
        return Err(AppError::Forbidden(
            "only owners and admins can remove delegates".into(),
        ));
    }

    let target_role = db::get_delegate_role(
        &state.db,
        state.db_backend,
        &input.account_did,
        &input.user_did,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("user is not a delegate of this account".into()))?;

    if target_role == DelegateRole::Owner {
        return Err(AppError::Forbidden(
            "cannot remove the owner — use unlinkAccount instead".into(),
        ));
    }

    if caller_role == DelegateRole::Admin && target_role == DelegateRole::Admin {
        return Err(AppError::Forbidden(
            "admins cannot remove other admins — only the owner can".into(),
        ));
    }

    db::remove_delegate(
        &state.db,
        state.db_backend,
        &input.account_did,
        &input.user_did,
    )
    .await?;

    log_event(
        &state.db,
        EventLog {
            event_type: "delegation.delegate_removed".to_string(),
            severity: Severity::Info,
            actor_did: Some(caller_did),
            subject: Some(input.user_did.clone()),
            detail: json!({
                "account_did": input.account_did,
            }),
        },
        state.db_backend,
    )
    .await;

    Ok((StatusCode::OK, Json(json!({}))).into_response())
}
