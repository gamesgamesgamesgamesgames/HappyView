use std::collections::HashMap;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::AppState;
use crate::db::{adapt_sql, now_rfc3339};
use crate::error::AppError;

use super::auth::UserAuth;
use super::permissions::Permission;

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
pub(super) struct RecordLabel {
    pub src: String,
    pub val: String,
    pub cts: String,
}

#[derive(Serialize)]
pub(super) struct RecordEntry {
    pub uri: String,
    pub did: String,
    pub record: Value,
    pub labels: Vec<RecordLabel>,
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
    auth: UserAuth,
    Query(params): Query<ListRecordsParams>,
) -> Result<Json<ListRecordsResponse>, AppError> {
    auth.require(Permission::RecordsRead).await?;
    let backend = state.db_backend;
    let limit = params.limit.unwrap_or(20).min(100);
    let offset: i64 = params
        .cursor
        .as_deref()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);

    let sql = adapt_sql(
        "SELECT uri, did, record FROM records WHERE collection = $1 ORDER BY indexed_at DESC LIMIT $2 OFFSET $3",
        backend,
    );
    let rows: Vec<(String, String, String)> = sqlx::query_as(&sql)
        .bind(&params.collection)
        .bind(limit + 1)
        .bind(offset)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to list records: {e}")))?;

    let has_more = rows.len() as i64 > limit;
    let visible_rows: Vec<(String, String, String)> =
        rows.into_iter().take(limit as usize).collect();

    // Batch-query external labels for all visible URIs
    let uris: Vec<&str> = visible_rows
        .iter()
        .map(|(uri, _, _)| uri.as_str())
        .collect();

    let label_rows: Vec<(String, String, String, String)> = if uris.is_empty() {
        Vec::new()
    } else {
        let now = now_rfc3339();
        let placeholders: Vec<String> = (1..=uris.len()).map(|i| format!("${i}")).collect();
        let ph_str = placeholders.join(", ");
        let next_idx = uris.len() + 1;
        let raw_sql = format!(
            "SELECT uri, src, val, cts FROM labels WHERE uri IN ({ph_str}) AND (exp IS NULL OR exp > ${next_idx})"
        );
        let sql = adapt_sql(&raw_sql, backend);
        let mut q = sqlx::query_as(&sql);
        for uri in &uris {
            q = q.bind(*uri);
        }
        q = q.bind(&now);
        q.fetch_all(&state.db)
            .await
            .map_err(|e| AppError::Internal(format!("failed to fetch labels: {e}")))?
    };

    // Group external labels by URI
    let mut labels_by_uri: HashMap<String, Vec<RecordLabel>> = HashMap::new();
    for (uri, src, val, cts) in label_rows {
        labels_by_uri
            .entry(uri)
            .or_default()
            .push(RecordLabel { src, val, cts });
    }

    let records: Vec<RecordEntry> = visible_rows
        .into_iter()
        .map(|(uri, did, record_str)| {
            let record: Value = serde_json::from_str(&record_str).unwrap_or_default();
            let mut labels = labels_by_uri.remove(&uri).unwrap_or_default();

            // Extract self-labels from record JSONB
            if let Some(values) = record
                .get("labels")
                .and_then(|l| l.get("values"))
                .and_then(|v| v.as_array())
            {
                for entry in values {
                    if let Some(val) = entry.get("val").and_then(|v| v.as_str()) {
                        labels.push(RecordLabel {
                            src: did.clone(),
                            val: val.to_string(),
                            cts: String::new(),
                        });
                    }
                }
            }

            RecordEntry {
                uri,
                did,
                record,
                labels,
            }
        })
        .collect();

    let cursor = if has_more {
        Some((offset + limit).to_string())
    } else {
        None
    };

    Ok(Json(ListRecordsResponse { records, cursor }))
}

#[derive(Deserialize)]
pub(super) struct DeleteCollectionParams {
    pub collection: String,
}

/// DELETE /admin/records/collection?collection=X — delete all records in a collection.
pub(super) async fn delete_collection_records(
    State(state): State<AppState>,
    auth: UserAuth,
    Query(params): Query<DeleteCollectionParams>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require(Permission::RecordsDeleteCollection).await?;
    auth.require(Permission::RecordsDelete).await?;
    let backend = state.db_backend;
    let sql = adapt_sql("DELETE FROM records WHERE collection = $1", backend);
    let result = sqlx::query(&sql)
        .bind(&params.collection)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete records: {e}")))?;

    Ok(Json(
        serde_json::json!({ "deleted": result.rows_affected() }),
    ))
}

/// DELETE /admin/records?uri=at://... — delete a single record by URI.
pub(super) async fn delete_record(
    State(state): State<AppState>,
    auth: UserAuth,
    Query(params): Query<DeleteRecordParams>,
) -> Result<StatusCode, AppError> {
    auth.require(Permission::RecordsDelete).await?;
    let backend = state.db_backend;
    let sql = adapt_sql("DELETE FROM records WHERE uri = $1", backend);
    let result = sqlx::query(&sql)
        .bind(&params.uri)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete record: {e}")))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("record not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}
