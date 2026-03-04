use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;

use crate::AppState;
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};

use super::auth::AdminAuth;
use super::types::{ScriptVariableSummary, UpsertScriptVariableBody};

/// GET /admin/script-variables — list all variables with masked preview.
pub(super) async fn list(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<Vec<ScriptVariableSummary>>, AppError> {
    let rows: Vec<(
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "SELECT key, value, created_at, updated_at FROM script_variables ORDER BY key",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to list script variables: {e}")))?;

    let vars: Vec<ScriptVariableSummary> = rows
        .into_iter()
        .map(|(key, value, created_at, updated_at)| {
            let preview = mask_value(&value);
            ScriptVariableSummary {
                key,
                preview,
                created_at,
                updated_at,
            }
        })
        .collect();

    Ok(Json(vars))
}

/// POST /admin/script-variables — create or update a variable.
pub(super) async fn upsert(
    State(state): State<AppState>,
    auth: AdminAuth,
    Json(body): Json<UpsertScriptVariableBody>,
) -> Result<StatusCode, AppError> {
    sqlx::query(
        r#"
        INSERT INTO script_variables (key, value)
        VALUES ($1, $2)
        ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()
        "#,
    )
    .bind(&body.key)
    .bind(&body.value)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to upsert script variable: {e}")))?;

    log_event(
        &state.db,
        EventLog {
            event_type: "script_variable.upserted".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(body.key.clone()),
            detail: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /admin/script-variables/{key} — delete a variable.
pub(super) async fn delete(
    State(state): State<AppState>,
    auth: AdminAuth,
    Path(key): Path<String>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query("DELETE FROM script_variables WHERE key = $1")
        .bind(&key)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete script variable: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "script variable '{key}' not found"
        )));
    }

    log_event(
        &state.db,
        EventLog {
            event_type: "script_variable.deleted".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(key),
            detail: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Show first 4 characters then asterisks, or just asterisks for short values.
fn mask_value(value: &str) -> String {
    if value.len() <= 4 {
        "*".repeat(value.len())
    } else {
        format!("{}****", &value[..4])
    }
}
