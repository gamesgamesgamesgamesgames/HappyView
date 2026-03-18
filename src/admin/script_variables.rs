use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;

use crate::AppState;
use crate::db::{adapt_sql, now_rfc3339};
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};

use super::auth::UserAuth;
use super::permissions::Permission;
use super::types::{ScriptVariableSummary, UpsertScriptVariableBody};

/// GET /admin/script-variables — list all variables with masked preview.
pub(super) async fn list(
    State(state): State<AppState>,
    auth: UserAuth,
) -> Result<Json<Vec<ScriptVariableSummary>>, AppError> {
    auth.require(Permission::ScriptVariablesRead).await?;

    let backend = state.db_backend;
    let sql = adapt_sql(
        "SELECT key, value, created_at, updated_at FROM script_variables ORDER BY key",
        backend,
    );
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(&sql)
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
    auth: UserAuth,
    Json(body): Json<UpsertScriptVariableBody>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::ScriptVariablesCreate).await?;

    let backend = state.db_backend;
    let now = now_rfc3339();
    let sql = adapt_sql(
        r#"
        INSERT INTO script_variables (key, value, created_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = $3
        "#,
        backend,
    );
    sqlx::query(&sql)
        .bind(&body.key)
        .bind(&body.value)
        .bind(&now)
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
        state.db_backend,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /admin/script-variables/{key} — delete a variable.
pub(super) async fn delete(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(key): Path<String>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::ScriptVariablesDelete).await?;

    let backend = state.db_backend;
    let sql = adapt_sql("DELETE FROM script_variables WHERE key = $1", backend);
    let result = sqlx::query(&sql)
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
        state.db_backend,
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
