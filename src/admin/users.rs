use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde_json::Value;

use crate::AppState;
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};

use super::auth::UserAuth;
use super::permissions::Permission;
use super::types::{CreateUserBody, TransferSuperBody, UpdatePermissionsBody, UserSummary};

/// POST /admin/users — create a new user with template or explicit permissions.
pub(super) async fn create_user(
    State(state): State<AppState>,
    auth: UserAuth,
    Json(body): Json<CreateUserBody>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    auth.require(Permission::UsersCreate).await?;

    // Determine permissions to grant
    let perms_to_grant: Vec<String> = if let Some(explicit) = &body.permissions {
        explicit.clone()
    } else if let Some(template) = &body.template {
        template
            .permissions()
            .iter()
            .map(|p| p.as_str().to_string())
            .collect()
    } else {
        // Default to viewer
        super::permissions::Template::Viewer
            .permissions()
            .iter()
            .map(|p| p.as_str().to_string())
            .collect()
    };

    // Escalation guard: actor can only grant permissions they hold
    if !auth.is_super {
        for perm_str in &perms_to_grant {
            #[allow(clippy::collapsible_if)]
            if let Ok(p) =
                serde_json::from_value::<Permission>(serde_json::Value::String(perm_str.clone()))
            {
                if !auth.permissions.contains(&p) {
                    return Err(AppError::Forbidden(format!(
                        "Cannot grant permission you don't have: {perm_str}"
                    )));
                }
            }
        }
    }

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(format!("transaction start failed: {e}")))?;

    let row: (String,) = sqlx::query_as("INSERT INTO users (did) VALUES ($1) RETURNING id::text")
        .bind(&body.did)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("failed to create user: {e}")))?;

    let user_id = &row.0;

    for perm_str in &perms_to_grant {
        sqlx::query(
            "INSERT INTO user_permissions (user_id, permission, granted_by)
             VALUES ($1::uuid, $2, $3::uuid)
             ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(perm_str)
        .bind(&auth.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("failed to grant permission: {e}")))?;
    }

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(format!("transaction commit failed: {e}")))?;

    let template_name = body
        .template
        .as_ref()
        .map(|t| format!("{t:?}").to_lowercase());

    log_event(
        &state.db,
        EventLog {
            event_type: "user.created".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(body.did.clone()),
            detail: serde_json::json!({
                "template": template_name,
                "permissions": perms_to_grant,
            }),
        },
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": user_id,
            "did": body.did,
        })),
    ))
}

/// GET /admin/users — list all users with their permissions.
pub(super) async fn list_users(
    State(state): State<AppState>,
    auth: UserAuth,
) -> Result<Json<Vec<UserSummary>>, AppError> {
    auth.require(Permission::UsersRead).await?;

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        bool,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = sqlx::query_as(
        "SELECT id::text, did, is_super, created_at, last_used_at
         FROM users ORDER BY created_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to list users: {e}")))?;

    let mut users = Vec::new();
    for (id, did, is_super, created_at, last_used_at) in rows {
        let perm_rows: Vec<(String,)> = sqlx::query_as(
            "SELECT permission FROM user_permissions WHERE user_id = $1::uuid ORDER BY permission",
        )
        .bind(&id)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to load permissions: {e}")))?;

        users.push(UserSummary {
            id,
            did,
            is_super,
            permissions: perm_rows.into_iter().map(|(p,)| p).collect(),
            created_at,
            last_used_at,
        });
    }

    Ok(Json(users))
}

/// GET /admin/users/:id — get a single user with permissions.
pub(super) async fn get_user(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(id): Path<String>,
) -> Result<Json<UserSummary>, AppError> {
    auth.require(Permission::UsersRead).await?;

    #[allow(clippy::type_complexity)]
    let found: Option<(
        String,
        String,
        bool,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = sqlx::query_as(
        "SELECT id::text, did, is_super, created_at, last_used_at
         FROM users WHERE id::text = $1",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to get user: {e}")))?;

    let Some((uid, did, is_super, created_at, last_used_at)) = found else {
        return Err(AppError::NotFound(format!("user '{id}' not found")));
    };

    let perm_rows: Vec<(String,)> = sqlx::query_as(
        "SELECT permission FROM user_permissions WHERE user_id = $1::uuid ORDER BY permission",
    )
    .bind(&uid)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to load permissions: {e}")))?;

    Ok(Json(UserSummary {
        id: uid,
        did,
        is_super,
        permissions: perm_rows.into_iter().map(|(p,)| p).collect(),
        created_at,
        last_used_at,
    }))
}

/// PATCH /admin/users/:id/permissions — grant/revoke permissions.
pub(super) async fn update_permissions(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(id): Path<String>,
    Json(body): Json<UpdatePermissionsBody>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::UsersUpdate).await?;

    // Self-modification guard
    if auth.user_id == id {
        return Err(AppError::Forbidden(
            "Cannot modify your own permissions".into(),
        ));
    }

    // Cannot modify super user's permissions
    let target: Option<(bool,)> = sqlx::query_as("SELECT is_super FROM users WHERE id::text = $1")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("user lookup failed: {e}")))?;

    let Some((target_is_super,)) = target else {
        return Err(AppError::NotFound(format!("user '{id}' not found")));
    };

    if target_is_super {
        return Err(AppError::Forbidden(
            "Cannot modify super user's permissions".into(),
        ));
    }

    // Validate all permission strings are recognized
    for perm_str in body.grant.iter().chain(body.revoke.iter()) {
        if serde_json::from_value::<Permission>(serde_json::Value::String(perm_str.clone()))
            .is_err()
        {
            return Err(AppError::BadRequest(format!(
                "Unrecognized permission: {perm_str}"
            )));
        }
    }

    // Escalation guard: can only grant permissions you hold
    if !auth.is_super {
        for perm_str in &body.grant {
            #[allow(clippy::collapsible_if)]
            if let Ok(p) =
                serde_json::from_value::<Permission>(serde_json::Value::String(perm_str.clone()))
            {
                if !auth.permissions.contains(&p) {
                    return Err(AppError::Forbidden(format!(
                        "Cannot grant permission you don't have: {perm_str}"
                    )));
                }
            }
        }
    }

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(format!("transaction start failed: {e}")))?;

    for perm_str in &body.grant {
        sqlx::query(
            "INSERT INTO user_permissions (user_id, permission, granted_by)
             VALUES ($1::uuid, $2, $3::uuid)
             ON CONFLICT DO NOTHING",
        )
        .bind(&id)
        .bind(perm_str)
        .bind(&auth.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("failed to grant permission: {e}")))?;
    }

    for perm_str in &body.revoke {
        sqlx::query(
            "DELETE FROM user_permissions
             WHERE user_id = $1::uuid AND permission = $2",
        )
        .bind(&id)
        .bind(perm_str)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("failed to revoke permission: {e}")))?;
    }

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(format!("transaction commit failed: {e}")))?;

    log_event(
        &state.db,
        EventLog {
            event_type: "user.permissions_updated".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(id.clone()),
            detail: serde_json::json!({
                "granted": body.grant,
                "revoked": body.revoke,
            }),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /admin/users/:id — remove a user.
pub(super) async fn delete_user(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::UsersDelete).await?;

    // Self-deletion guard
    if auth.user_id == id {
        return Err(AppError::Forbidden("Cannot delete yourself".into()));
    }

    // Cannot delete super user
    let target: Option<(bool,)> = sqlx::query_as("SELECT is_super FROM users WHERE id::text = $1")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("user lookup failed: {e}")))?;

    let Some((is_super,)) = target else {
        return Err(AppError::NotFound(format!("user '{id}' not found")));
    };

    if is_super {
        return Err(AppError::Forbidden("Cannot delete the super user".into()));
    }

    // Delete cascades to user_permissions; also revoke their API keys.
    // Use a transaction for atomicity.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(format!("transaction start failed: {e}")))?;

    sqlx::query(
        "UPDATE api_keys SET revoked_at = NOW() WHERE user_id = $1::uuid AND revoked_at IS NULL",
    )
    .bind(&id)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(format!("failed to revoke api keys: {e}")))?;

    let result = sqlx::query("DELETE FROM users WHERE id::text = $1")
        .bind(&id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete user: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("user '{id}' not found")));
    }

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(format!("transaction commit failed: {e}")))?;

    log_event(
        &state.db,
        EventLog {
            event_type: "user.deleted".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(id),
            detail: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /admin/users/transfer-super — transfer super user status.
pub(super) async fn transfer_super(
    State(state): State<AppState>,
    auth: UserAuth,
    Json(body): Json<TransferSuperBody>,
) -> Result<StatusCode, AppError> {
    if !auth.is_super {
        return Err(AppError::Forbidden(
            "Only the super user can transfer super status".into(),
        ));
    }

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(format!("transaction start failed: {e}")))?;

    // Remove super from current user
    sqlx::query("UPDATE users SET is_super = FALSE WHERE id::text = $1")
        .bind(&auth.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("failed to remove super: {e}")))?;

    // Set super on target user
    let result = sqlx::query("UPDATE users SET is_super = TRUE WHERE id::text = $1")
        .bind(&body.target_user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("failed to set super: {e}")))?;

    if result.rows_affected() == 0 {
        // Rollback by not committing
        return Err(AppError::NotFound(format!(
            "user '{}' not found",
            body.target_user_id
        )));
    }

    // Ensure target has all permissions
    for perm in Permission::all() {
        sqlx::query(
            "INSERT INTO user_permissions (user_id, permission, granted_by)
             VALUES ($1::uuid, $2, $3::uuid)
             ON CONFLICT DO NOTHING",
        )
        .bind(&body.target_user_id)
        .bind(perm.as_str())
        .bind(&auth.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("failed to grant permission: {e}")))?;
    }

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(format!("transaction commit failed: {e}")))?;

    log_event(
        &state.db,
        EventLog {
            event_type: "user.super_transferred".to_string(),
            severity: Severity::Warn,
            actor_did: Some(auth.did.clone()),
            subject: Some(body.target_user_id.clone()),
            detail: serde_json::json!({
                "from_user_id": auth.user_id,
                "to_user_id": body.target_user_id,
            }),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}
