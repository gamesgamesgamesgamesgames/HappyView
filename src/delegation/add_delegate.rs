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
pub struct AddDelegateInput {
    pub account_did: String,
    pub user_did: String,
    pub role: String,
}

pub async fn add_delegate(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Json(input): Json<AddDelegateInput>,
) -> Result<Response, AppError> {
    let claims = xrpc_claims
        .0
        .ok_or_else(|| AppError::Auth("addDelegate requires authentication".into()))?;

    let caller_did = claims.did().to_string();

    super::verify_client_scope(&state, &claims, &input.account_did).await?;

    let caller_role =
        db::get_delegate_role(&state.db, state.db_backend, &input.account_did, &caller_did)
            .await?
            .ok_or_else(|| AppError::Forbidden("you are not a delegate of this account".into()))?;

    if !caller_role.can_manage_members() {
        return Err(AppError::Forbidden(
            "only owners and admins can add delegates".into(),
        ));
    }

    let target_role = match input.role.as_str() {
        "admin" => DelegateRole::Admin,
        "member" => DelegateRole::Member,
        "owner" => {
            return Err(AppError::BadRequest(
                "cannot add a second owner — use unlinkAccount and re-link instead".into(),
            ));
        }
        _ => {
            return Err(AppError::BadRequest(
                "role must be 'admin' or 'member'".into(),
            ));
        }
    };

    let existing = db::get_delegate_role(
        &state.db,
        state.db_backend,
        &input.account_did,
        &input.user_did,
    )
    .await?;
    if existing.is_some() {
        return Err(AppError::Conflict(
            "user is already a delegate — remove them first to change role".into(),
        ));
    }

    db::add_delegate(
        &state.db,
        state.db_backend,
        &input.account_did,
        &input.user_did,
        target_role,
        &caller_did,
    )
    .await?;

    log_event(
        &state.db,
        EventLog {
            event_type: "delegation.delegate_added".to_string(),
            severity: Severity::Info,
            actor_did: Some(caller_did),
            subject: Some(input.user_did.clone()),
            detail: json!({
                "account_did": input.account_did,
                "role": input.role,
            }),
        },
        state.db_backend,
    )
    .await;

    Ok((StatusCode::CREATED, Json(json!({}))).into_response())
}
