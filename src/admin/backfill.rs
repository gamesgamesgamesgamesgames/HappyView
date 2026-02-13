use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde_json::Value;

use crate::AppState;
use crate::error::AppError;

use super::auth::AdminAuth;
use super::types::{BackfillJob, CreateBackfillBody};

/// POST /admin/backfill — create a new backfill job.
pub(super) async fn create_backfill(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<CreateBackfillBody>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let row: (String,) = sqlx::query_as(
        "INSERT INTO backfill_jobs (collection, did) VALUES ($1, $2) RETURNING id::text",
    )
    .bind(&body.collection)
    .bind(&body.did)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to create backfill job: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": row.0,
            "status": "pending",
        })),
    ))
}

/// GET /admin/backfill/status — list all backfill jobs.
pub(super) async fn backfill_status(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<Vec<BackfillJob>>, AppError> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        Option<String>,
        Option<String>,
        String,
        Option<i32>,
        Option<i32>,
        Option<i32>,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "SELECT id::text, collection, did, status, total_repos, processed_repos, total_records, error, started_at, completed_at, created_at FROM backfill_jobs ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to list backfill jobs: {e}")))?;

    let jobs: Vec<BackfillJob> = rows
        .into_iter()
        .map(
            |(
                id,
                collection,
                did,
                status,
                total_repos,
                processed_repos,
                total_records,
                error,
                started_at,
                completed_at,
                created_at,
            )| {
                BackfillJob {
                    id,
                    collection,
                    did,
                    status,
                    total_repos,
                    processed_repos,
                    total_records,
                    error,
                    started_at,
                    completed_at,
                    created_at,
                }
            },
        )
        .collect();

    Ok(Json(jobs))
}
