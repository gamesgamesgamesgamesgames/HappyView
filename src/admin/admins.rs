use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde_json::Value;

use crate::AppState;
use crate::error::AppError;

use super::auth::AdminAuth;
use super::types::{AdminSummary, CreateAdminBody};

/// POST /admin/admins — add a new admin by DID.
pub(super) async fn create_admin(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<CreateAdminBody>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let row: (String,) =
        sqlx::query_as("INSERT INTO admins (did) VALUES ($1) RETURNING id::text")
            .bind(&body.did)
            .fetch_one(&state.db)
            .await
            .map_err(|e| AppError::Internal(format!("failed to create admin: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": row.0,
            "did": body.did,
        })),
    ))
}

/// GET /admin/admins — list all admins.
pub(super) async fn list_admins(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<Vec<AdminSummary>>, AppError> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = sqlx::query_as(
        "SELECT id::text, did, created_at, last_used_at FROM admins ORDER BY created_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to list admins: {e}")))?;

    let admins: Vec<AdminSummary> = rows
        .into_iter()
        .map(|(id, did, created_at, last_used_at)| AdminSummary {
            id,
            did,
            created_at,
            last_used_at,
        })
        .collect();

    Ok(Json(admins))
}

/// DELETE /admin/admins/:id — remove an admin.
pub(super) async fn delete_admin(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query("DELETE FROM admins WHERE id::text = $1")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete admin: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("admin '{id}' not found")));
    }

    Ok(StatusCode::NO_CONTENT)
}
