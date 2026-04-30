pub mod add_delegate;
pub mod db;
pub mod get_account;
pub mod link_account;
pub mod list_accounts;
pub mod list_delegates;
pub mod remove_delegate;
pub mod unlink_account;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegatedAccountView {
    pub did: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegateView {
    pub user_did: String,
    pub role: String,
    pub granted_by: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegateRole {
    Owner,
    Admin,
    Member,
}

impl DelegateRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            DelegateRole::Owner => "owner",
            DelegateRole::Admin => "admin",
            DelegateRole::Member => "member",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(DelegateRole::Owner),
            "admin" => Some(DelegateRole::Admin),
            "member" => Some(DelegateRole::Member),
            _ => None,
        }
    }

    pub fn can_write(&self) -> bool {
        matches!(self, DelegateRole::Owner | DelegateRole::Admin)
    }

    pub fn can_manage_members(&self) -> bool {
        matches!(self, DelegateRole::Owner | DelegateRole::Admin)
    }
}

pub(crate) async fn resolve_caller_client_id(
    state: &crate::AppState,
    claims: &crate::auth::Claims,
) -> Result<String, crate::error::AppError> {
    let client_key = claims.client_key().ok_or_else(|| {
        crate::error::AppError::Auth("delegation requires DPoP authentication".into())
    })?;
    crate::repo::get_dpop_client_id(state, client_key).await
}

pub(crate) async fn verify_client_scope(
    state: &crate::AppState,
    claims: &crate::auth::Claims,
    account_did: &str,
) -> Result<(), crate::error::AppError> {
    let caller_client_id = resolve_caller_client_id(state, claims).await?;

    let stored_client_id = db::get_api_client_id(&state.db, state.db_backend, account_did)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("delegated account not found".into()))?;

    if caller_client_id != stored_client_id {
        return Err(crate::error::AppError::Forbidden(
            "delegation is scoped to a different application".into(),
        ));
    }

    Ok(())
}
