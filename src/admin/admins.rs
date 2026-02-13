use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::Value;

use crate::AppState;
use crate::error::AppError;

use super::auth::AdminAuth;
use super::hash::hash_api_key;
use super::types::{AdminSummary, CreateAdminBody};

/// POST /admin/admins — create a new admin. Returns the API key once.
pub(super) async fn create_admin(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<CreateAdminBody>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let api_key = uuid::Uuid::new_v4().to_string();
    let key_hash = hash_api_key(&api_key);

    let row: (String,) = sqlx::query_as(
        "INSERT INTO admins (name, api_key_hash) VALUES ($1, $2) RETURNING id::text",
    )
    .bind(&body.name)
    .bind(&key_hash)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to create admin: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": row.0,
            "name": body.name,
            "api_key": api_key,
        })),
    ))
}

/// GET /admin/admins — list all admins (without keys).
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
        "SELECT id::text, name, created_at, last_used_at FROM admins ORDER BY created_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to list admins: {e}")))?;

    let admins: Vec<AdminSummary> = rows
        .into_iter()
        .map(|(id, name, created_at, last_used_at)| AdminSummary {
            id,
            name,
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
