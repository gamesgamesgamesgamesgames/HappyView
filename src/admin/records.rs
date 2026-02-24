use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::AppState;
use crate::error::AppError;

use super::auth::AdminAuth;

#[derive(Deserialize)]
pub(super) struct ListRecordsParams {
    pub collection: String,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DeleteRecordParams {
    pub uri: String,
}

#[derive(Serialize)]
pub(super) struct RecordEntry {
    pub uri: String,
    pub did: String,
    pub record: Value,
}

#[derive(Serialize)]
pub(super) struct ListRecordsResponse {
    pub records: Vec<RecordEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// GET /admin/records?collection=X&limit=N&cursor=C — browse records by collection.
pub(super) async fn list_records(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Query(params): Query<ListRecordsParams>,
) -> Result<Json<ListRecordsResponse>, AppError> {
    let limit = params.limit.unwrap_or(20).min(100);
    let offset: i64 = params
        .cursor
        .as_deref()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);

    let rows: Vec<(String, String, Value)> = sqlx::query_as(
        "SELECT uri, did, record FROM records WHERE collection = $1 ORDER BY indexed_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&params.collection)
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("failed to list records: {e}")))?;

    let has_more = rows.len() as i64 > limit;
    let records: Vec<RecordEntry> = rows
        .into_iter()
        .take(limit as usize)
        .map(|(uri, did, record)| RecordEntry { uri, did, record })
        .collect();

    let cursor = if has_more {
        Some((offset + limit).to_string())
    } else {
        None
    };

    Ok(Json(ListRecordsResponse { records, cursor }))
}

/// DELETE /admin/records?uri=at://... — delete a single record by URI.
pub(super) async fn delete_record(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Query(params): Query<DeleteRecordParams>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query("DELETE FROM records WHERE uri = $1")
        .bind(&params.uri)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete record: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("record not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}
