use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;

use crate::AppState;
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};

use super::auth::UserAuth;
use super::permissions::Permission;
use super::types::{AddLabelerBody, LabelerSummary, UpdateLabelerBody};

/// GET /admin/labelers — list all labeler subscriptions.
pub(super) async fn list(
    State(state): State<AppState>,
    auth: UserAuth,
) -> Result<Json<Vec<LabelerSummary>>, AppError> {
    auth.require(Permission::LabelersRead).await?;

    let labelers: Vec<LabelerSummary> = sqlx::query_as(
        "SELECT did, status, cursor, created_at, updated_at FROM labeler_subscriptions ORDER BY created_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to list labeler subscriptions: {e}")))?;

    Ok(Json(labelers))
}

/// POST /admin/labelers — add a labeler subscription.
pub(super) async fn add(
    State(state): State<AppState>,
    auth: UserAuth,
    Json(body): Json<AddLabelerBody>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::LabelersCreate).await?;

    sqlx::query(
        r#"
        INSERT INTO labeler_subscriptions (did)
        VALUES ($1)
        ON CONFLICT (did) DO UPDATE SET status = 'active', updated_at = NOW()
        "#,
    )
    .bind(&body.did)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to add labeler subscription: {e}")))?;

    // Notify the labeler consumer to pick up the new subscription.
    let _ = state.labeler_subscriptions_tx.send(());

    log_event(
        &state.db,
        EventLog {
            event_type: "labeler.added".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(body.did.clone()),
            detail: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::CREATED)
}

/// PATCH /admin/labelers/{did} — update labeler status (active/paused).
pub(super) async fn update(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(did): Path<String>,
    Json(body): Json<UpdateLabelerBody>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::LabelersCreate).await?;

    let result = sqlx::query(
        "UPDATE labeler_subscriptions SET status = $1, updated_at = NOW() WHERE did = $2",
    )
    .bind(&body.status)
    .bind(&did)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to update labeler subscription: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "labeler subscription '{did}' not found"
        )));
    }

    let _ = state.labeler_subscriptions_tx.send(());

    log_event(
        &state.db,
        EventLog {
            event_type: "labeler.updated".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(did),
            detail: serde_json::json!({ "status": body.status }),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /admin/labelers/{did} — remove a labeler subscription and its labels.
pub(super) async fn delete(
    State(state): State<AppState>,
    auth: UserAuth,
    Path(did): Path<String>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::LabelersDelete).await?;

    let result = sqlx::query("DELETE FROM labeler_subscriptions WHERE did = $1")
        .bind(&did)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete labeler subscription: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "labeler subscription '{did}' not found"
        )));
    }

    // Also remove all labels from this labeler.
    let _ = sqlx::query("DELETE FROM labels WHERE src = $1")
        .bind(&did)
        .execute(&state.db)
        .await;

    let _ = state.labeler_subscriptions_tx.send(());

    log_event(
        &state.db,
        EventLog {
            event_type: "labeler.deleted".to_string(),
            severity: Severity::Info,
            actor_did: Some(auth.did.clone()),
            subject: Some(did),
            detail: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}
